/* The engine rule under a hostile peer (lobby.h, ERRORS; composite-node.md
 * 8.1): no call of the lobby engine returns an error for anything a peer, the
 * key port or a user command can cause.
 *
 * A deterministic randomized run, for a seed. A host and then a member are
 * each thrown, for ITERATIONS inputs:
 *   - messages of every kind (0 to 65535 sampled, the lobby's own and their
 *     neighbours most often), with random records, valid signed messages,
 *     valid messages mutated, wrong scopes, no scope, the other side's kinds;
 *   - on its own links, on links it holds no connection for, on links that
 *     are not its own at all;
 *   - connections and disconnections in any order, also twice;
 *   - timers of every identifier, the lobby's and any other;
 *   - user commands at any time, also when they make no sense;
 *   - a crypto port that refuses to sign at random;
 *   - the clock moving on, also past the deadline.
 * Among them, honest steps (join, ready, answer a check) so that the deep
 * states are reached: checks, starts, Signing, retries, Funding.
 *
 * After every call:
 *   - it returned GZ_OK. gz_lobby_host_set_values is given only values inside
 *     the terms' ranges here, and gz_lobby_host_open only good records with a
 *     port that signs (what they refuse otherwise is a person's mistake,
 *     checked in test_lobby_v2.c);
 *   - the action list, of 256 slots and 512 KiB as lobby.h asks, did not
 *     overflow (an overflow is an error, so it would show as one);
 *   - every record saved is within its row of the table of largest records;
 *   - every SEND decodes and is on a link of the engine's own; every
 *     DISCONNECT is a refusal on such a link.
 * And, now and then and at every end: the records saved so far, given to a
 * fresh engine, are all taken (GZ_OK), it resumes (GZ_OK), and what it holds
 * is what the running engine holds (the host: state, freeze, version, seats,
 * starts, budget, end; the member: seat, freeze, answer, start).
 *
 * usage: test_lobby_hostile [ITERATIONS [SEED]]   (CTest: lobby_hostile) */
#include "../check.h"
#include "lobby_test.h"
#include "rng.h"
#include <stdlib.h>

#define NMEM 40
#define DEADLINE_MS 1794441600000ull

static sim_rng_t R;
static lt_signer_t HOST, OTHER, MEM[NMEM];
static uint8_t T1[512], T2[128], T3[128], SCOPE[32], CD[4][32];
static size_t T1N, T2N, T3N;
static gz_terms_outer_t T1O;
static uint8_t BO[GZ_TERMS_OUTER_MAX], BC[GZ_TERMS_CURRENT_MAX], BSCOPE[32];
static size_t BON, BCN;
static uint64_t NOW;
static uint32_t FAIL_PM;             /* how often the port refuses to sign, per mille */

static unsigned long IT, FAILS, MAX_COUNT, MAX_USED, N_SAVED, N_SENT, N_REFUSALS, N_NO_KEY, N_RESTORES, N_SCEN,
                     N_SIGNING, N_ENDED, N_REFUSED_SIGN, N_BEGUN, N_CMD_REFUSED, N_LOCKED, N_CONNECT, N_SEATED, N_FUNDED;

static void fail(const char *what, long v)
{
    if (FAILS < 25) printf("FAIL at input %lu: %s (%ld)\n", IT, what, v);
    FAILS++;
}
#define OK(call, what) do { gz_status_t st__ = (call); if (st__ != GZ_OK) fail(what, (long)st__); } while (0)
#define MUST(cond, what) do { if (!(cond)) fail(what, 0); } while (0)

static uint64_t rnd(uint64_t n) { return sim_rng_below(&R, n); }
static int one_in(uint64_t n) { return sim_rng_below(&R, n) == 0; }

static uint64_t c_now(void *ctx) { (void)ctx; return NOW; }
static void c_rand(void *ctx, gz_random_purpose_t p, uint8_t *o, size_t n) { (void)ctx; (void)p; sim_rng_fill(&R, o, n); }

/* The crypto port: the test keys, and a signer that refuses at random. */
static int h_sign(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64])
{
    if (FAIL_PM && sim_rng_chance(&R, FAIL_PM)) { N_REFUSED_SIGN++; return 0; }
    return lt_sign(ctx, which, msg, sig);
}
static gz_lobby_crypto_t crypto(lt_signer_t *s)
{
    gz_lobby_crypto_t c = lt_crypto(s);
    c.sign = h_sign;
    return c;
}
static gz_ports_t ports(void)
{
    gz_ports_t p;
    p.random.fill = c_rand; p.random.ctx = NULL;
    p.clock.now_ms = c_now; p.clock.ctx = NULL;
    return p;
}

/* The action list lobby.h asks for: 256 slots, 512 KiB. */
static gz_action_t SL[256];
static uint8_t BY[512 * 1024];
static gz_action_list_t L;
static void lreset(void) { gz_action_list_init(&L, SL, 256, BY, sizeof BY); }

/* ---- the journal: every record saved, in order ---- */

typedef struct { gz_record_t *r; size_t n, cap; } journal_t;

static void j_free(journal_t *j)
{
    size_t i;
    for (i = 0; i < j->n; i++) free((void *)j->r[i].bytes.data);
    j->n = 0;
}

/* Look at the list a call left, and keep its saves. `local` is the key every
 * link of this engine has as its own end. */
static void absorb(journal_t *j, const uint8_t local[33])
{
    size_t i, k;
    gz_lobby_msg_t m;
    if (L.count > MAX_COUNT) MAX_COUNT = L.count;
    if (L.used > MAX_USED) MAX_USED = L.used;
    for (i = 0; i < L.count; i++) {
        const gz_action_t *a = &L.slots[i];
        switch (a->kind) {
        case GZ_ACTION_SAVE:
            for (k = 0; k < a->u.save.n_records; k++) {
                gz_record_t r = a->u.save.records[k];
                uint8_t *b = malloc(r.bytes.len + 1);
                MUST(lt_rec_fits(r.type, r.bytes.len), "a saved record over its row of the table");
                if (!b) { fail("no memory", 0); return; }
                memcpy(b, r.bytes.data, r.bytes.len);
                r.bytes.data = b;
                if (j->n == j->cap) {
                    j->cap = j->cap ? 2 * j->cap : 256;
                    j->r = realloc(j->r, j->cap * sizeof *j->r);
                }
                j->r[j->n++] = r;
                N_SAVED++;
            }
            break;
        case GZ_ACTION_SEND:
            N_SENT++;
            MUST(lt_send_decode(a, &m) == GZ_DEC_OK, "a SEND that does not decode");
            MUST(memcmp(a->u.send.link.local.key, local, 33) == 0, "a SEND on a link that is not the engine's");
            break;
        case GZ_ACTION_DISCONNECT:
            N_REFUSALS++;
            MUST(a->u.disconnect.why == GZ_DISCONNECT_REFUSED, "a DISCONNECT that is no refusal");
            MUST(memcmp(a->u.disconnect.link.local.key, local, 33) == 0, "a DISCONNECT on a link that is not the engine's");
            break;
        case GZ_ACTION_NOTIFY:
            if (a->u.notify.code == GZ_NOTE_NO_KEY) N_NO_KEY++;
            if (a->u.notify.code == GZ_NOTE_COMMAND_REFUSED) N_CMD_REFUSED++;
            if (a->u.notify.code == GZ_NOTE_LOCKED) N_LOCKED++;
            break;
        case GZ_ACTION_CONNECT: N_CONNECT++; break;
        case GZ_ACTION_SET_SEATED: N_SEATED++; break;
        case GZ_ACTION_SET_TIMER: break;
        default: fail("an action the lobby never issues", (long)a->kind);
        }
    }
}

static int in_list(uint32_t note)
{
    size_t i;
    for (i = 0; i < L.count; i++)
        if (L.slots[i].kind == GZ_ACTION_NOTIFY && L.slots[i].u.notify.code == note) return 1;
    return 0;
}

/* ---- envelopes ---- */

static uint8_t ENV[70000];           /* the message being built */
static size_t ENVN;

static void e_hello(const uint8_t *scope)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, ENV, sizeof ENV, GZ_KIND_HELLO, scope);
    ENVN = gz_lobby_enc_done(&e);
}

/* K1: a join carries no factory key and no binding. The faults the join used to carry (another member's
 * factory key, a spoiled binding) are kept for that member's next ready, which now names them. */
static int K1_FKEY_OF[NMEM], K1_SPOIL[NMEM], K1_SET[NMEM];
static void e_join(const uint8_t *scope, int who, int fkey_of, int spoil)
{
    gz_lobby_enc_t e;
    K1_FKEY_OF[who] = fkey_of; K1_SPOIL[who] = spoil; K1_SET[who] = 1;
    gz_lobby_enc_start(&e, ENV, sizeof ENV, GZ_KIND_JOIN, scope);
    if (one_in(5)) gz_lobby_enc_record(&e, 7, (const uint8_t *)"a name", 6);
    ENVN = gz_lobby_enc_done(&e);
}

static void e_ready(const uint8_t *scope, lt_signer_t *signer, uint32_t version, const uint8_t *digest, const uint8_t *check,
                    uint16_t min, size_t pad)
{
    static uint8_t padb[120];
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(signer);
    gz_lobby_enc_start(&e, ENV, sizeof ENV, GZ_KIND_READY, scope);
    gz_lobby_enc_record(&e, 2, scope, 32);
    gz_lobby_enc_u32(&e, 4, version);
    gz_lobby_enc_record(&e, 6, digest, 32);
    if (check) gz_lobby_enc_record(&e, 8, check, 32);
    if (pad) gz_lobby_enc_record(&e, 9, padb, pad);
    if (min) gz_lobby_enc_u16(&e, 11, min);
    {   /* K1: the factory key (the one the member's join meant, maybe another's) and the binding (maybe spoiled) */
        int who = signer >= MEM && signer < MEM + NMEM ? (int)(signer - MEM) : 0;
        int f = K1_SET[who] ? K1_FKEY_OF[who] : who;
        uint8_t b[32], sc[64];
        gz_lobby_binding(scope, MEM[f].key[3].pub, signer->key[2].pub, b);
        lt_sign(signer, 2, b, sc);
        if (K1_SET[who] && K1_SPOIL[who]) sc[rnd(64)] ^= 1;
        gz_lobby_enc_record(&e, 12, MEM[f].key[3].pub, 33);
        gz_lobby_enc_record(&e, 14, sc, 64);
    }
    ENVN = gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_CONTRIBUTION);
}

static void e_reason(const uint8_t *scope, uint16_t kind, int reason)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, ENV, sizeof ENV, kind, scope);
    if (reason >= 0) gz_lobby_enc_u16(&e, 1, (uint16_t)reason);
    ENVN = gz_lobby_enc_done(&e);
}

static void e_offer(const uint8_t *scope, const uint8_t *o, size_t on, const uint8_t *c, size_t cn, lt_signer_t *signer)
{
    uint8_t od[32], cd[32], os[64], cs[64];
    gz_lobby_enc_t e;
    gz_terms_outer_digest(o, on, od);
    gz_terms_current_digest(c, cn, cd);
    lt_sign(signer, 1, od, os);
    lt_sign(signer, 1, cd, cs);
    gz_lobby_enc_start(&e, ENV, sizeof ENV, GZ_KIND_TERMS_OFFER, scope);
    gz_lobby_enc_record(&e, 2, o, on);
    gz_lobby_enc_record(&e, 4, os, 64);
    gz_lobby_enc_record(&e, 6, c, cn);
    gz_lobby_enc_record(&e, 8, cs, 64);
    ENVN = gz_lobby_enc_done(&e);
}

static void e_status(const uint8_t *scope, uint8_t lobby, uint8_t seat, uint32_t version, int reason)
{
    gz_lobby_enc_t e;
    gz_lobby_enc_start(&e, ENV, sizeof ENV, GZ_KIND_LOBBY_STATUS, scope);
    gz_lobby_enc_u8(&e, 2, lobby); gz_lobby_enc_u8(&e, 4, seat); gz_lobby_enc_u32(&e, 6, version);
    gz_lobby_enc_u16(&e, 8, (uint16_t)rnd(9)); gz_lobby_enc_u16(&e, 10, (uint16_t)rnd(9));
    if (reason >= 0) gz_lobby_enc_u16(&e, 13, (uint16_t)reason);
    ENVN = gz_lobby_enc_done(&e);
}

static void e_host(const uint8_t *scope, uint16_t kind, const uint8_t *check, uint32_t version, const uint8_t *digest,
                   uint32_t window, uint8_t role, uint16_t signers, uint16_t reason, size_t pad, lt_signer_t *signer)
{
    static uint8_t padb[400];
    gz_lobby_enc_t e;
    gz_lobby_crypto_t cr = lt_crypto(signer);
    gz_lobby_enc_start(&e, ENV, sizeof ENV, kind, scope);
    if (kind == GZ_KIND_READY_CHECK) {
        gz_lobby_enc_record(&e, 2, check, 32);
        gz_lobby_enc_u32(&e, 4, version);
        gz_lobby_enc_record(&e, 6, digest, 32);
        gz_lobby_enc_u32(&e, 8, window);
        if (pad) gz_lobby_enc_record(&e, 9, padb, pad);
    } else if (kind == GZ_KIND_START) {
        gz_lobby_enc_record(&e, 2, check, 32);
        gz_lobby_enc_u8(&e, 4, role);
        gz_lobby_enc_u16(&e, 6, signers);
        if (pad) gz_lobby_enc_record(&e, 7, padb, pad);
    } else {
        gz_lobby_enc_u16(&e, 2, reason);
        if (pad) gz_lobby_enc_record(&e, 3, padb, pad);
    }
    ENVN = gz_lobby_enc_sign(&e, &cr, GZ_LOBBY_KEY_HOST);
}

/* Spoil the records of the envelope in ENV: flips, edges, truncation,
 * insertion, a doubled slice. The header (tag, kind, scope) is left. */
static void e_mutate(void)
{
    size_t rounds = 1 + (size_t)rnd(3), r, n = ENVN - GZ_LOBBY_ENV_HDR, at, len;
    uint8_t *p = ENV + GZ_LOBBY_ENV_HDR;
    static const uint8_t edge[] = {0x00, 0x01, 0x02, 0x20, 0x40, 0x7f, 0x80, 0xf0, 0xfc, 0xfd, 0xfe, 0xff};
    for (r = 0; r < rounds; r++) {
        at = n ? (size_t)rnd(n) : 0;
        switch (rnd(6)) {
        case 0: if (n) p[at] ^= (uint8_t)(1u << rnd(8)); break;
        case 1: if (n) p[at] = edge[rnd(sizeof edge)]; break;
        case 2: n = at; break;
        case 3: len = 1 + (size_t)rnd(40);
            if (n + len < 60000) { memmove(p + at + len, p + at, n - at); sim_rng_fill(&R, p + at, len); n += len; }
            break;
        case 4: len = n - at;
            if (len && n + len < 60000) { memcpy(p + n, p + at, len); n += len; }
            break;
        default: len = 1 + (size_t)rnd(16);
            if (at + len <= n) { memmove(p + at, p + at + len, n - at - len); n -= len; }
            break;
        }
    }
    ENVN = GZ_LOBBY_ENV_HDR + n;
}

/* A kind: the lobby's, their neighbours, the other engines', or any of 0 to 65535. */
static uint16_t any_kind(void)
{
    static const uint16_t near[] = {0, 1, 2, 3, 15, 16, 17, 18, 20, 22, 24, 26, 28, 30, 32, 34, 35, 36, 62, 64, 81, 82, 127,
                                    128, 159, 160, 255, 256, 32768, 65534, 65535};
    switch (rnd(4)) {
    case 0: return near[rnd(sizeof near / sizeof near[0])];
    case 1: return (uint16_t)(16 + 2 * rnd(10));
    default: return (uint16_t)rnd(65536);
    }
}

/* A MESSAGE of any kind with random records, under `scope`, a scope of zeros,
 * a random one or none at all. */
static void in_random(gz_lobby_input_t *in, const gz_link_t *l, const uint8_t *scope)
{
    static uint8_t rec[70000], sc[32];
    size_t n = one_in(40) ? (size_t)rnd(sizeof rec) : (size_t)rnd(400);
    sim_rng_fill(&R, rec, n < 2000 ? n : 2000);          /* the rest stays as it was: random enough */
    lt_in(in, GZ_LIN_MESSAGE, l);
    in->msg_kind = any_kind();
    in->records = rec;
    in->len = n;
    switch (rnd(8)) {
    case 0: memset(sc, 0, 32); in->scope = sc; break;
    case 1: sim_rng_fill(&R, sc, 32); in->scope = sc; break;
    case 2: in->scope = NULL; break;
    default: in->scope = scope; break;
    }
    if (one_in(30)) { in->records = NULL; in->len = one_in(2) ? 0 : n; }
}

/* T1 with target 32 and a display record filling it to 4,096 bytes; its current record. */
static void big_terms(void)
{
    static gz_terms_outer_t o;
    static uint8_t enc[GZ_TERMS_OUTER_MAX];
    gz_terms_current_t c;
    gz_lw_tlv_t t;
    size_t en, at, pad, start;
    o = T1O;
    o.target = 32;
    o.shapes[1].max_members = 40;
    en = gz_terms_encode_outer(&o, enc, sizeof enc);
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
    gz_terms_outer_digest(BO, BON, BSCOPE);
    CHECK(en > 0 && BON == GZ_TERMS_OUTER_MAX && lt_outer(BO, BON, &o));
    CHECK(lt_current(T2, T2N, &T1O, SCOPE, &c));
    memcpy(c.outer_digest, BSCOPE, 32);
    BCN = gz_terms_encode_current(&c, BC, sizeof BC);
    CHECK(BCN > 0);
}

/* ================================================================ the host */

static gz_lobby_host_t H, HR;
static journal_t HJ;
static const uint8_t *HSC;           /* this scenario's scope */
static int H_LIVE_FOR;               /* inputs left before the next scenario, once the lobby ended */
static uint8_t UNKNOWN_KEY[33];

static gz_status_t hs_begin(void *ctx, const gz_lobby_handoff_t *ho, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    N_BEGUN++;
    MUST(ho->role == 1 && ho->participants && ho->n_participants == ho->signers && ho->n_participants >= 2 &&
         ho->attempt == 1 && ho->budget_end_ms == H.budget_ms + H.terms.signing_budget_ms && H.budget_ms != 0 &&
         ho->n_levels != 0, "the host's hand-off");
    return GZ_OK;
}
static gz_status_t hs_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    MUST(memcmp(scope, HSC, 32) == 0 && reason >= 1 && reason <= 3, "the cancel given to the signing engine");
    return GZ_OK;
}
static gz_status_t hs_left(void *ctx, const uint8_t scope[32], const uint8_t ckey[33], gz_action_list_t *out)
{
    (void)ctx; (void)scope; (void)ckey; (void)out;
    return GZ_OK;
}

static void host_init(gz_lobby_host_t *h, uint16_t standbys, int listed)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = crypto(&HOST);
    gz_lobby_host_config_t cfg;
    gz_lobby_signing_t sg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    cfg.standbys = standbys;
    cfg.listed = listed;
    sg.begin = hs_begin; sg.cancel = hs_cancel; sg.member_left = hs_left; sg.ctx = NULL;
    OK(gz_lobby_host_init(h, &p, &cr, &sg, &cfg), "host_init");
}

static uint16_t H_STANDBYS;

static void host_scenario(void)
{
    int big = one_in(4);
    j_free(&HJ);
    N_SCEN++;
    FAIL_PM = 0;                                        /* a host whose port will not sign opens nothing: not this test */
    H_STANDBYS = big ? 0 : (uint16_t)rnd(3);
    NOW = DEADLINE_MS - (2 + rnd(30)) * 60000;
    host_init(&H, H_STANDBYS, (int)rnd(2));
    lreset();
    if (big) { HSC = BSCOPE; OK(gz_lobby_host_open(&H, BO, BON, BC, BCN, &L), "host_open (4,096 bytes of terms)"); }
    else { HSC = SCOPE; OK(gz_lobby_host_open(&H, T1, T1N, T2, T2N, &L), "host_open"); }
    absorb(&HJ, HOST.key[1].pub);
    H_LIVE_FOR = 0;
}

static gz_lobby_seat_t *h_seat(gz_lobby_host_t *h, const uint8_t key[33])
{
    uint16_t i;
    for (i = 0; i < h->n_seats; i++) if (memcmp(h->seats[i].ckey, key, 33) == 0) return &h->seats[i];
    return NULL;
}

static int h_conn(const uint8_t key[33])
{
    int i;
    for (i = 0; i < GZ_LOBBY_MAX_CONNS; i++) if (H.conns[i].used && memcmp(H.conns[i].key, key, 33) == 0) return 1;
    return 0;
}

/* The records saved so far, in a fresh host: all taken, it resumes, and it
 * holds what the running host holds. */
static void host_restore_check(void)
{
    size_t i;
    uint16_t k;
    uint32_t pm = FAIL_PM;
    N_RESTORES++;
    host_init(&HR, H_STANDBYS, H.cfg.listed);
    for (i = 0; i < HJ.n; i++) OK(gz_lobby_host_restore(&HR, &HJ.r[i]), "host_restore of a record the host saved");
    lreset();
    OK(gz_lobby_host_resume(&HR, &L), "host_resume");
    FAIL_PM = pm;
    {   /* resume re-announces every seat and sets no budget timer in Signing */
        size_t q;
        int seated = 0, budget = 0, live = 0;
        for (q = 0; q < L.count; q++) {
            seated += L.slots[q].kind == GZ_ACTION_SET_SEATED && L.slots[q].u.set_seated.seated == 1;
            budget += L.slots[q].kind == GZ_ACTION_SET_TIMER && L.slots[q].u.set_timer.timer_id == GZ_LOBBY_TIMER_BUDGET;
            MUST(L.slots[q].kind != GZ_ACTION_SAVE && L.slots[q].kind != GZ_ACTION_SEND, "resume saved or sent");
        }
        for (k = 0; k < HR.n_seats; k++)
            live += HR.seats[k].state == GZ_SEAT_JOINED || HR.seats[k].state == GZ_SEAT_READY ||
                    (HR.state == GZ_LOBBY_SIGNING && HR.seats[k].chosen);
        MUST(seated == live, "resume: one SET_SEATED for every seat");
        MUST(budget == (HR.state == GZ_LOBBY_OPEN && HR.budget_ms != 0), "resume: the budget timer only with no round in flight");
    }
    MUST(HR.state == (H.state == GZ_LOBBY_READY_CHECK ? GZ_LOBBY_OPEN : H.state), "restored host: state");
    MUST(HR.frozen == H.frozen && HR.values.version == H.values.version && memcmp(HR.current_digest, H.current_digest, 32) == 0 &&
         memcmp(HR.scope, H.scope, 32) == 0, "restored host: values and freeze");
    MUST(HR.n_seats == H.n_seats && HR.budget_ms == H.budget_ms && HR.end_reason == H.end_reason &&
         HR.cancel_len == H.cancel_len && memcmp(HR.cancel_msg, H.cancel_msg, H.cancel_len) == 0 && HR.started == H.started,
         "restored host: seats, budget, end");
    if (H.state == GZ_LOBBY_SIGNING) MUST(memcmp(HR.check_id, H.check_id, 32) == 0, "restored host: the check of the round");
    for (k = 0; k < H.n_seats && k < HR.n_seats; k++) {
        const gz_lobby_seat_t *a = &H.seats[k], *b = &HR.seats[k];
        MUST(memcmp(a->ckey, b->ckey, 33) == 0 && memcmp(a->fkey, b->fkey, 33) == 0 && a->state == b->state &&
             a->min_members == b->min_members && a->ready_version == b->ready_version && a->join_seq == b->join_seq &&
             a->ready_len == b->ready_len && memcmp(a->ready_msg, b->ready_msg, a->ready_len) == 0, "restored host: a seat");
        if (H.state == GZ_LOBBY_SIGNING)
            MUST(a->chosen == b->chosen && a->start_len == b->start_len && memcmp(a->start_msg, b->start_msg, a->start_len) == 0,
                 "restored host: a seat's start");
    }
}

/* One input to the host. */
static void host_step(void)
{
    gz_lobby_input_t in;
    gz_link_t l;
    int who = (int)rnd(one_in(4) ? NMEM : 10), op = (int)rnd(100), k;
    const uint8_t *key;
    gz_lobby_seat_t *s;
    int was = H.state;
    if (op < 38 && H.check_open && one_in(2)) {
        /* an honest step while a check is open: a seat that has not answered yet does */
        uint16_t at = (uint16_t)rnd(H.n_seats ? H.n_seats : 1), q;
        for (q = 0; q < H.n_seats; q++) {
            const gz_lobby_seat_t *t = &H.seats[(at + q) % H.n_seats];
            if (!t->answered && (t->state == GZ_SEAT_JOINED || t->state == GZ_SEAT_READY) && h_conn(t->ckey)) {
                for (k = 0; k < NMEM; k++) if (memcmp(MEM[k].key[2].pub, t->ckey, 33) == 0) who = k;
                break;
            }
        }
    }
    key = MEM[who].key[2].pub;
    if (op >= 38 && one_in(25)) { sim_rng_fill(&R, UNKNOWN_KEY, 33); key = UNKNOWN_KEY; who = 0; }
    /* every link the node part gives a host has the host's key as its own end:
     * a peer chooses only the other one */
    l = lt_link(HOST.key[1].pub, key);
    s = h_seat(&H, key);
    lreset();
    if (op < 38) {
        /* an honest step for this key: connect, join, ready, answer the open check */
        if (!h_conn(key)) { lt_in(&in, GZ_LIN_CONNECTED, &l); OK(gz_lobby_host_handle(&H, &in, &L), "host: CONNECTED"); }
        else {
            if (!s || (s->state != GZ_SEAT_JOINED && s->state != GZ_SEAT_READY)) e_join(HSC, who, who, 0);
            else e_ready(HSC, &MEM[who], H.values.version, H.current_digest, H.check_open ? H.check_id : NULL, 0, 0);
            if (lt_in_env(&in, &l, ENV, ENVN)) OK(gz_lobby_host_handle(&H, &in, &L), "host: an honest message");
        }
    } else if (op < 42) {
        lt_in(&in, GZ_LIN_CONNECTED, &l);
        OK(gz_lobby_host_handle(&H, &in, &L), "host: CONNECTED");
    } else if (op < 45) {
        lt_in(&in, GZ_LIN_DISCONNECTED, &l);
        OK(gz_lobby_host_handle(&H, &in, &L), "host: DISCONNECTED");
    } else if (op < 62) {
        /* a member's message, valid in form: every kind, with every twist */
        static uint8_t osc[32];
        const uint8_t *sc = HSC;
        uint8_t chk[32];
        memcpy(osc, HSC, 32);
        osc[rnd(32)] ^= 0x10;
        if (one_in(12)) sc = osc;
        sim_rng_fill(&R, chk, 32);
        switch (rnd(9)) {
        case 0: e_hello(one_in(6) ? osc : sc); break;
        case 1: e_join(sc, who, one_in(4) ? (int)rnd(NMEM) : who, one_in(6)); break;
        case 2: case 3: case 4:
            k = (int)rnd(8);
            e_ready(sc, one_in(10) ? &MEM[rnd(NMEM)] : &MEM[who],
                    k == 0 ? (uint32_t)rnd(5) : H.values.version, k == 1 ? chk : H.current_digest,
                    k == 2 ? chk : (H.check_open || one_in(4)) ? H.check_id : NULL,
                    one_in(4) ? (uint16_t)rnd(40) : 0, one_in(10) ? (size_t)rnd(100) : 0);
            break;
        case 5: e_reason(sc, GZ_KIND_UNREADY, one_in(3) ? -1 : (int)rnd(5)); break;
        case 6: e_reason(sc, one_in(5) ? GZ_KIND_LEAVE : GZ_KIND_UNREADY, one_in(3) ? -1 : (int)rnd(5)); break;
        case 7:                                         /* the host's own kinds, sent to it */
            if (one_in(2)) e_status(sc, (uint8_t)rnd(8), (uint8_t)rnd(8), (uint32_t)rnd(4), one_in(2) ? -1 : (int)rnd(6));
            else e_host(sc, (uint16_t)(GZ_KIND_READY_CHECK + 2 * rnd(3)), chk, 1, H.current_digest, 30000, 1, 4, 2, 0,
                        one_in(2) ? &HOST : &OTHER);
            break;
        default: e_offer(sc, T1, T1N, T2, T2N, &HOST); break;
        }
        if (one_in(4)) e_mutate();
        if (lt_in_env(&in, &l, ENV, ENVN)) {
            if (one_in(30)) in.msg_kind = any_kind();
            OK(gz_lobby_host_handle(&H, &in, &L), "host: a member's message");
        }
    } else if (op < 72) {
        in_random(&in, &l, HSC);
        OK(gz_lobby_host_handle(&H, &in, &L), "host: a random message");
    } else if (op < 80) {
        static const uint64_t T[] = {GZ_LOBBY_TIMER_DEADLINE, GZ_LOBBY_TIMER_WINDOW, GZ_LOBBY_TIMER_WINDOW, GZ_LOBBY_TIMER_WINDOW,
                                     GZ_LOBBY_TIMER_STATUS, GZ_LOBBY_TIMER_RETRY, 0x4c000005u, GZ_LOBBY_TIMER_BUDGET, 0, 1,
                                     0x4c000000u, 0x4c000007u, 0xffffffffffffffffull};
        lt_in(&in, GZ_LIN_TIMER, one_in(2) ? &l : NULL);
        in.timer_id = one_in(8) ? sim_rng_u64(&R) : T[rnd(sizeof T / sizeof T[0])];
        OK(gz_lobby_host_handle(&H, &in, &L), "host: a timer");
        if (was == GZ_LOBBY_SIGNING && in.timer_id == GZ_LOBBY_TIMER_BUDGET)
            MUST(L.count == 0 && H.state == GZ_LOBBY_SIGNING, "the lobby's budget timer acted on a round in flight");
    } else if (op < 86) {
        NOW += one_in(6) ? rnd(120) * 1000 : rnd(3000);
    } else if (op < 96) {
        uint64_t v[GZ_TERMS_MAX_ADJ];
        uint8_t failed[3 * 33];
        switch (rnd(12)) {
        case 0: case 1: case 2:                         /* new values, inside the ranges */
            for (k = 0; k < H.terms.n_adj; k++) v[k] = H.terms.adj[k].min + rnd(H.terms.adj[k].max - H.terms.adj[k].min + 1);
            OK(gz_lobby_host_set_values(&H, v, H.terms.n_adj, &L), "host_set_values");
            break;
        case 3: case 4:
            if (one_in(8)) OK(gz_lobby_host_remove(&H, key, &L), "host_remove");
            else OK(gz_lobby_host_listing(&H, &l, &L), "host_listing");
            break;
        case 5:
            if (one_in(40)) OK(gz_lobby_host_cancel(&H, (uint16_t)(1 + rnd(3)), &L), "host_cancel");
            break;
        case 6: case 7: case 8:                         /* the signing engine: a retry naming seats, some unknown */
            for (k = 0; k < 3; k++) memcpy(failed + 33 * k, MEM[rnd(NMEM)].key[2].pub, 33);
            OK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_RETRY, failed, (size_t)rnd(4), &L), "host_round_result (retry)");
            break;
        case 9:
            OK(gz_lobby_host_round_result(&H, one_in(2) ? GZ_LOBBY_ROUND_FUNDING : GZ_LOBBY_ROUND_ACTIVE, NULL, 0, &L),
               "host_round_result (funding or active)");
            if (!in_list(GZ_NOTE_COMMAND_REFUSED)) N_FUNDED++;
            break;
        case 10:
            if (one_in(8)) OK(gz_lobby_host_round_result(&H, GZ_LOBBY_ROUND_FAILED, NULL, 0, &L), "host_round_result (failed)");
            break;
        default:
            OK(gz_lobby_host_listing(&H, &l, &L), "host_listing");
            break;
        }
    } else {
        static const uint32_t pm[] = {0, 0, 0, 0, 50, 300, 1000};
        FAIL_PM = pm[rnd(sizeof pm / sizeof pm[0])];
    }
    absorb(&HJ, HOST.key[1].pub);
    /* Signing: no budget timer of the lobby's while a round is in flight */
    if (H.state == GZ_LOBBY_SIGNING) {
        size_t q;
        for (q = 0; q < L.count; q++)
            MUST(!(L.slots[q].kind == GZ_ACTION_SET_TIMER && L.slots[q].u.set_timer.timer_id == GZ_LOBBY_TIMER_BUDGET),
                 "a budget timer set with a round in flight");
    }
    {   /* a DISCONNECT is carried out: the transport closes that link, and says so */
        gz_link_t cut[4];
        size_t n_cut = 0, q;
        for (q = 0; q < L.count && n_cut < 4; q++)
            if (L.slots[q].kind == GZ_ACTION_DISCONNECT) cut[n_cut++] = L.slots[q].u.disconnect.link;
        for (q = 0; q < n_cut; q++) {
            lt_in(&in, GZ_LIN_DISCONNECTED, &cut[q]);
            lreset();
            OK(gz_lobby_host_handle(&H, &in, &L), "host: DISCONNECTED after its refusal");
            MUST(L.count == 0, "a disconnection made the host act");
        }
    }
    if (was != GZ_LOBBY_SIGNING && H.state == GZ_LOBBY_SIGNING) N_SIGNING++;
    if (H.state == GZ_LOBBY_SIGNING) MUST(gz_lobby_host_round_ok(&H), "Signing without round_ok");
    if (one_in(60) || (was < GZ_LOBBY_FUNDING && H.state >= GZ_LOBBY_FUNDING)) host_restore_check();
    if (H.state >= GZ_LOBBY_FUNDING) {
        if (was < GZ_LOBBY_FUNDING) { N_ENDED++; H_LIVE_FOR = 30 + (int)rnd(200); }
        else if (--H_LIVE_FOR <= 0) { host_restore_check(); host_scenario(); }
    }
}

/* ============================================================== the member */

static gz_lobby_member_t M, MR;
static journal_t MJ;
static gz_link_t MLK;
static int GATE_USED, GATE_OPEN, M_LIVE_FOR;
static uint8_t CHECKS[4][32];
static uint8_t CUR[8][GZ_TERMS_CURRENT_MAX];     /* current records of versions 1 to 5, and three others */
static size_t CURN[8];
static uint8_t CURD[8][32];

static int m_gate(void *ctx, const uint8_t scope[32])
{
    (void)ctx;
    MUST(memcmp(scope, SCOPE, 32) == 0, "the gate asked for another scope");
    return GATE_OPEN;
}

static gz_status_t ms_begin(void *ctx, const gz_lobby_handoff_t *ho, gz_action_list_t *out)
{
    gz_lobby_handoff_t acc;
    (void)ctx; (void)out;
    N_BEGUN++;
    MUST(gz_lobby_member_accepted(&M, ho->check_id, 1, &acc) || gz_lobby_member_accepted(&MR, ho->check_id, 1, &acc),
         "begin for a check the member has not accepted");
    MUST(ho->role == 1 && ho->start_len != 0 && ho->limits && ho->attempt == 1 && ho->budget_end_ms == 0 &&
         ho->participants == NULL, "the member's hand-off");
    return GZ_OK;
}
static gz_status_t ms_cancel(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out)
{
    (void)ctx; (void)out;
    MUST(memcmp(scope, SCOPE, 32) == 0 && reason >= 1, "the cancel given to the member's signing engine");
    return GZ_OK;
}

static gz_lobby_conditions_t any_cond(void)
{
    gz_lobby_conditions_t c = lt_cond_fits();
    if (one_in(4)) LT_ADJ(c, 0) = one_in(2) ? 400 : 1000;
    if (one_in(8)) c.limits.min_channel_sat = 100001;
    c.current_only = (uint8_t)rnd(2);
    c.min_members = one_in(3) ? (uint16_t)rnd(10) : 0;
    return c;
}

static void member_init(gz_lobby_member_t *m)
{
    gz_ports_t p = ports();
    gz_lobby_crypto_t cr = crypto(&MEM[1]);
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_lobby_signing_t sg;
    gz_lobby_gate_t gate;
    sg.begin = ms_begin; sg.cancel = ms_cancel; sg.member_left = NULL; sg.ctx = NULL;
    gate.may_answer = m_gate; gate.ctx = NULL;
    OK(lt_member_init(m, &p, &cr, &sg, GATE_USED ? &gate : NULL, &cond, SCOPE, HOST.key[1].pub, MEM[1].key[2].pub,
                      MEM[1].key[3].pub, (int)rnd(8) != 0), "member_init");
}

static void member_scenario(void)
{
    j_free(&MJ);
    N_SCEN++;
    FAIL_PM = 0;
    GATE_USED = (int)rnd(2);
    GATE_OPEN = 1;
    NOW = DEADLINE_MS - (5 + rnd(120)) * 60000;
    member_init(&M);
    M_LIVE_FOR = 0;
    lreset();
    OK(gz_lobby_member_connect(&M, &L), "member_connect");
    MUST(L.count == 1 && lt_is_connect(&L.slots[0], HOST.key[1].pub), "the member's CONNECT");
    absorb(&MJ, MEM[1].key[2].pub);
}

/* The member's records in a fresh member: all taken, it resumes with its
 * CONNECT first, and its seat is the running member's. */
static void member_restore_check(void)
{
    size_t i;
    int open = GATE_OPEN;
    int auto_join = M.auto_join;
    N_RESTORES++;
    member_init(&MR);
    MR.auto_join = auto_join;
    for (i = 0; i < MJ.n; i++) OK(gz_lobby_member_restore(&MR, &MJ.r[i]), "member_restore of a record the member saved");
    if (!M.ended) {
        MUST(MR.joined == M.joined && MR.ready == M.ready && MR.frozen == M.frozen, "restored member: its seat");
        if (M.frozen) MUST(MR.frozen_version == M.frozen_version && memcmp(MR.frozen_digest, M.frozen_digest, 32) == 0,
                           "restored member: the freeze");
        MUST(MR.has_answered == M.has_answered && (!M.has_answered || memcmp(MR.answered_check, M.answered_check, 32) == 0),
             "restored member: its answer");
        MUST(MR.start_len == M.start_len && memcmp(MR.start_msg, M.start_msg, M.start_len) == 0 && MR.role == M.role,
             "restored member: its start");
        MUST(MR.round_state == M.round_state, "restored member: the round's outcome");
        if (M.ready) MUST(MR.ready_len == M.ready_len && memcmp(MR.ready_msg, M.ready_msg, M.ready_len) == 0 &&
                          MR.ready_version == M.ready_version, "restored member: its ready");
    }
    MUST(MR.left == M.left, "restored member: left");
    GATE_OPEN = (int)rnd(2);                            /* gates are closed at a start; or there is none */
    lreset();
    OK(gz_lobby_member_resume(&MR, &L), "member_resume");
    MUST(L.count >= 1 && lt_is_connect(&L.slots[0], HOST.key[1].pub), "resume: the member's CONNECT first");
    {
        size_t q;
        for (q = 0; q < L.count; q++) MUST(L.slots[q].kind != GZ_ACTION_SEND, "resume sent before any connection");
    }
    GATE_OPEN = open;
}

static void member_step(void)
{
    gz_lobby_input_t in;
    gz_link_t l = MLK;
    int op = (int)rnd(100), k, was_ended = M.ended, closed0 = GATE_USED && !GATE_OPEN, gate_moved = 0;
    size_t saved0 = MJ.n, q;
    if (one_in(30)) l = lt_link(MEM[1].key[2].pub, OTHER.key[1].pub);          /* another host */
    if (one_in(60)) l = lt_link(MEM[2].key[2].pub, HOST.key[1].pub);           /* another key of ours */
    lreset();
    if (op < 6) {
        lt_in(&in, one_in(3) ? GZ_LIN_DISCONNECTED : GZ_LIN_CONNECTED, &l);
        OK(gz_lobby_member_handle(&M, &in, &L), "member: a connection event");
    } else if (op < 52) {
        /* the host's messages, valid in form: every kind, with every twist */
        static uint8_t osc[32];
        const uint8_t *sc = SCOPE, *chk = CHECKS[rnd(one_in(3) ? 4 : 2)];
        uint32_t ver;
        if (!M.connected && !one_in(6)) { lt_in(&in, GZ_LIN_CONNECTED, &MLK); OK(gz_lobby_member_handle(&M, &in, &L), "member: CONNECTED"); goto done; }
        memcpy(osc, SCOPE, 32);
        osc[rnd(32)] ^= 0x10;
        if (one_in(15)) sc = osc;
        k = one_in(30) ? (int)rnd(8) : (int)rnd(2);      /* mostly versions 1 and 2 */
        ver = k < 5 ? (uint32_t)(k + 1) : k == 5 ? 2 : k == 6 ? 3 : 1;
        switch (rnd(12)) {
        case 0: case 1: case 2:
            e_offer(sc, T1, T1N, CUR[k], CURN[k], one_in(80) ? &OTHER : &HOST);
            break;
        case 3: case 4: case 5:
            if (M.have_terms && !one_in(4)) e_host(sc, GZ_KIND_READY_CHECK, chk, M.values.version, M.current_digest,
                                                  one_in(30) ? 29999 : 30000, 0, 0, 0, one_in(8) ? (size_t)rnd(120) : 0,
                                                  one_in(25) ? &OTHER : &HOST);
            else e_host(sc, GZ_KIND_READY_CHECK, chk, ver, CURD[k], 30000, 0, 0, 0, 0, &HOST);
            break;
        case 6: case 7:
            e_host(sc, GZ_KIND_START, M.has_answered && !one_in(4) ? M.answered_check : chk, 0, NULL, 0,
                   (uint8_t)(one_in(15) ? rnd(5) : 1 + rnd(2)), (uint16_t)(one_in(15) ? rnd(3) : 2 + rnd(8)), 0,
                   one_in(8) ? (size_t)rnd(120) : 0, one_in(25) ? &OTHER : &HOST);
            break;
        case 8: case 9:
            e_status(sc, (uint8_t)(one_in(3) ? rnd(8) : 1), (uint8_t)(one_in(15) ? rnd(8) : rnd(3)), (uint32_t)(1 + rnd(3)),
                     one_in(4) ? (int)rnd(7) : -1);
            break;
        case 10:
            if (one_in(30)) e_host(sc, GZ_KIND_CANCEL, NULL, 0, NULL, 0, 0, 0, (uint16_t)(1 + rnd(3)), one_in(3) ? (size_t)rnd(300) : 0,
                                  one_in(3) ? &OTHER : &HOST);
            else e_status(sc, 1, (uint8_t)(1 + rnd(2)), M.have_terms ? M.values.version : 1, -1);
            break;
        default:                                        /* a member's kinds, sent to a member */
            switch (rnd(4)) {
            case 0: e_hello(sc); break;
            case 1: e_join(sc, 1, 1, 0); break;
            case 2: e_ready(sc, &MEM[1], 1, CURD[0], NULL, 0, 0); break;
            default: e_reason(sc, one_in(2) ? GZ_KIND_UNREADY : GZ_KIND_LEAVE, (int)rnd(4)); break;
            }
            break;
        }
        if (one_in(5)) e_mutate();
        if (lt_in_env(&in, &l, ENV, ENVN)) {
            if (one_in(30)) in.msg_kind = any_kind();
            if (one_in(60)) in.scope = NULL;
            OK(gz_lobby_member_handle(&M, &in, &L), "member: the host's message");
        }
    } else if (op < 62) {
        in_random(&in, &l, SCOPE);
        OK(gz_lobby_member_handle(&M, &in, &L), "member: a random message");
    } else if (op < 68) {
        static const uint64_t T[] = {GZ_LOBBY_TIMER_RETRY, GZ_LOBBY_TIMER_RETRY, GZ_LOBBY_TIMER_DEADLINE, GZ_LOBBY_TIMER_WINDOW,
                                     GZ_LOBBY_TIMER_STATUS, 0x4c000005u, GZ_LOBBY_TIMER_BUDGET, 0, 0x4c000007u,
                                     0xffffffffffffffffull};
        lt_in(&in, GZ_LIN_TIMER, one_in(2) ? &l : NULL);
        in.timer_id = one_in(8) ? sim_rng_u64(&R) : T[rnd(sizeof T / sizeof T[0])];
        OK(gz_lobby_member_handle(&M, &in, &L), "member: a timer");
    } else if (op < 72) {
        NOW += one_in(6) ? rnd(120) * 1000 : rnd(3000);
    } else if (op < 96) {
        gz_lobby_conditions_t c;
        gz_lobby_handoff_t ho;
        switch (rnd(14)) {
        case 0: case 1: OK(gz_lobby_member_ready(&M, &L), "member_ready"); break;
        case 2: OK(gz_lobby_member_unready(&M, &L), "member_unready"); break;
        case 3: if (one_in(40)) OK(gz_lobby_member_leave(&M, &L), "member_leave"); break;
        case 4: case 5:
            c = any_cond();
            OK(gz_lobby_member_set_conditions(&M, &c, &L), "member_set_conditions");
            break;
        case 6: case 7: case 8:                         /* the gate moves, and the engine is told; or told without a move */
            if (GATE_USED && !one_in(6)) { GATE_OPEN = !GATE_OPEN; gate_moved = 1; }
            if (one_in(2) ? GATE_OPEN : one_in(2)) { OK(gz_lobby_member_gate_opened(&M, &L), "member_gate_opened"); gate_moved = 1; }
            else OK(gz_lobby_member_gate_closed(&M, &L), "member_gate_closed");
            break;
        case 9: case 10:                                /* the signing engine: an outcome, for a check it holds or any other */
            k = 1 + (int)rnd(4);
            if (k == GZ_LOBBY_ROUND_FUNDING || k == GZ_LOBBY_ROUND_ACTIVE) { if (!one_in(4)) k = GZ_LOBBY_ROUND_RETRY; }
            OK(gz_lobby_member_round_result(&M, k, M.has_answered && !one_in(3) ? M.answered_check : CHECKS[rnd(4)], &L),
               "member_round_result");
            break;
        case 11: OK(gz_lobby_member_connect(&M, &L), "member_connect"); break;
        default:                                        /* the signing engine asks: a proposal for any check, any attempt */
            k = gz_lobby_member_accepted(&M, one_in(2) ? M.answered_check : CHECKS[rnd(4)], (uint32_t)rnd(3), &ho);
            if (k) MUST(ho.role == 1 && ho.scope == M.scope && ho.check_id == M.answered_check && ho.version == M.frozen_version &&
                        M.ready && M.frozen && !M.ended && (ho.start_len == 0) == (ho.signers == 0), "the accepted record");
            (void)gz_lobby_member_round_ok(&M);
            break;
        }
    } else {
        static const uint32_t pm[] = {0, 0, 0, 0, 50, 300, 1000};
        FAIL_PM = pm[rnd(sizeof pm / sizeof pm[0])];
    }
done:
    absorb(&MJ, MEM[1].key[2].pub);
    /* a refusal ends the CONNECT: a member that goes on asks again, in the same list */
    for (q = 0; q < L.count; q++)
        if (L.slots[q].kind == GZ_ACTION_DISCONNECT) {
            MUST(memcmp(&L.slots[q].u.disconnect.link, &MLK, sizeof MLK) == 0 && !M.connected, "a refusal on another link");
            MUST(M.ended ? q + 1 == L.count || L.slots[q + 1].kind != GZ_ACTION_CONNECT
                         : q + 1 < L.count && lt_is_connect(&L.slots[q + 1], HOST.key[1].pub), "a refusal and its CONNECT");
        }
    /* no ready is signed while the gate is closed */
    if (closed0 && !gate_moved)
        for (q = saved0; q < MJ.n; q++) {
            const uint8_t *v;
            size_t vn;
            MUST(!(MJ.r[q].type == GZ_REC_READY_SENT && lt_rec_field(MJ.r[q].bytes.data, MJ.r[q].bytes.len, 4, &v, &vn)),
                 "a ready signed behind a closed gate");
        }
    if (one_in(40) || (!was_ended && M.ended)) member_restore_check();
    if (M.ended) {
        if (!was_ended) { N_ENDED++; M_LIVE_FOR = 20 + (int)rnd(120); }
        else if (--M_LIVE_FOR <= 0) member_scenario();
    }
}

/* Current records for the member's host: versions 1 to 5 inside the ranges,
 * then version 2 with other values (an equivocation against CUR[1]), version
 * 3 outside a range, and version 1 naming another outer record. */
static void member_terms(void)
{
    gz_terms_current_t c;
    int k;
    CHECK(lt_current(T2, T2N, &T1O, SCOPE, &c));
    for (k = 0; k < 8; k++) {
        gz_terms_current_t v = c;
        v.version = k < 5 ? (uint32_t)(k + 1) : k == 5 ? 2 : k == 6 ? 3 : 1;
        v.val[0].value = k < 5 ? 500 + 300u * (uint64_t)k : k == 5 ? 777 : k == 6 ? 2001 : 500;
        if (k == 7) v.outer_digest[0] ^= 1;
        CURN[k] = gz_terms_encode_current(&v, CUR[k], sizeof CUR[k]);
        CHECK(CURN[k] > 0);
        gz_terms_current_digest(CUR[k], CURN[k], CURD[k]);
    }
    for (k = 0; k < 4; k++) memset(CHECKS[k], 0x80 + k, 32);
}

int main(int argc, char **argv)
{
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 200000, n_host_scen, host_signing, host_ended, host_no_key;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    char label[64];
    int i;
    setvbuf(stdout, NULL, _IONBF, 0);
    sim_rng_init(&R, seed, 17);
    lt_key(&HOST.key[1], "host");
    lt_key(&HOST.key[3], "host factory");
    lt_key(&OTHER.key[1], "not the host");
    for (i = 0; i < NMEM; i++) {
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
    gz_terms_current_digest(T2, T2N, CD[1]);
    gz_terms_current_digest(T3, T3N, CD[2]);
    big_terms();
    member_terms();
    MLK = lt_link(MEM[1].key[2].pub, HOST.key[1].pub);

    host_scenario();
    for (IT = 0; IT < iters; IT++) host_step();
    host_restore_check();
    n_host_scen = N_SCEN; host_signing = N_SIGNING; host_ended = N_ENDED; host_no_key = N_NO_KEY;
    printf("hostile host: %lu inputs, %lu lobbies; %lu reached Signing, %lu ended, %lu funded; %lu records saved, %lu sends, "
           "%lu refusals, %lu SET_SEATED, %lu hand-offs; %lu signatures refused by the port, %lu NO_KEY notes; "
           "%lu restores; largest list %lu actions, %lu bytes\n",
           iters, n_host_scen, host_signing, host_ended, N_FUNDED, N_SAVED, N_SENT, N_REFUSALS, N_SEATED, N_BEGUN,
           N_REFUSED_SIGN, host_no_key, N_RESTORES, MAX_COUNT, MAX_USED);
    CHECK(MAX_COUNT <= 256 && MAX_USED <= sizeof BY);
    if (iters >= 20000) CHECK(host_signing > 0 && host_ended > 0 && N_REFUSALS > 0 && host_no_key > 0 && N_SEATED > 0 && N_BEGUN > 0);
    j_free(&HJ);
    free(HJ.r);

    N_SAVED = N_SENT = N_REFUSALS = N_NO_KEY = N_RESTORES = N_SCEN = N_ENDED = N_BEGUN = N_REFUSED_SIGN = N_CONNECT = N_LOCKED = 0;
    MAX_COUNT = MAX_USED = 0;
    member_scenario();
    for (IT = 0; IT < iters; IT++) member_step();
    member_restore_check();
    printf("hostile member: %lu inputs, %lu lobbies; %lu ended; %lu records saved, %lu sends, %lu refusals, %lu CONNECT, "
           "%lu hand-offs, %lu locked; %lu signatures refused by the port, %lu NO_KEY notes; %lu restores; "
           "largest list %lu actions, %lu bytes\n",
           iters, N_SCEN, N_ENDED, N_SAVED, N_SENT, N_REFUSALS, N_CONNECT, N_BEGUN, N_LOCKED, N_REFUSED_SIGN, N_NO_KEY,
           N_RESTORES, MAX_COUNT, MAX_USED);
    CHECK(MAX_COUNT <= 256 && MAX_USED <= sizeof BY);
    if (iters >= 20000) CHECK(N_ENDED > 0 && N_REFUSALS > 0 && N_NO_KEY > 0 && N_BEGUN > 0 && N_LOCKED > 0 && N_SAVED > 0);
    j_free(&MJ);
    free(MJ.r);
    CHECK(FAILS == 0);
    return check_done();
}
