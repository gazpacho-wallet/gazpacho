/* Fuzz target for every lobby decoder: the envelope and every lobby message
 * (as an envelope and as kind, scope and records), both terms records, the
 * host's and the member's record readers, and both engines fed the bytes as
 * a message. Beyond "no crash", each input checks: a decoded message's
 * fields lie inside its bytes; an accepted outer record with only known
 * types, and every accepted current record, re-encodes to exactly its bytes
 * (one encoding per set of terms); the record readers answer GZ_OK or
 * GZ_ERR_CORRUPT, under every record type, and never take a record larger
 * than its row of the table of largest records; the engines answer GZ_OK
 * (the engine rule: nothing a peer sends is an error). A failed check
 * aborts, so libFuzzer and the plain driver (fuzz_lobby_main.c,
 * docs/notes/ci.md) both report it.
 *
 * The engines are set up afresh for every input (copied from engines built
 * once: a host with one seat, a member that has joined and is ready, and
 * each as gz_lobby_*_init left it), so a finding repeats from its input
 * alone. Splitting (`part`) is the transport's: tests/net fuzzes it. */
#include "lobby_test.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
void lobby_fuzz_corpus(void (*add)(const uint8_t *b, size_t n));
unsigned long lobby_fuzz_stats[4];   /* accepted: messages, outer, current, records */

static int ready_;
static lt_signer_t HOST, MEM;
static uint8_t SCOPE[32], T1[512], T2[128];
static size_t T1N, T2N;
static gz_terms_outer_t T1O;
static uint64_t rnd;
static gz_link_t HL, ML;             /* the host's link to the member, and the member's to the host */

static uint64_t c_now(void *ctx) { (void)ctx; return 1794441000000ull; }
static void c_rand(void *ctx, gz_random_purpose_t p, uint8_t *o, size_t n)
{
    size_t i;
    (void)ctx; (void)p;
    for (i = 0; i < n; i++) {
        rnd ^= rnd << 13; rnd ^= rnd >> 7; rnd ^= rnd << 17;
        o[i] = (uint8_t)rnd;
    }
}

#define MUST(c) do { if (!(c)) { fprintf(stderr, "fuzz_lobby: %s\n", #c); abort(); } } while (0)

static gz_action_t slots[256];
static uint8_t abytes[1 << 19];
static gz_action_list_t L;
static void lreset(void) { gz_action_list_init(&L, slots, 256, abytes, sizeof abytes); }

/* The engines every input starts from. */
static gz_lobby_host_t H_NEW, H_OPEN, H_SEAT;      /* as init left it; opened, the member connected; and seated */
static gz_lobby_member_t M_NEW, M_CONN, M_READY;   /* as init left it; connected; joined and ready */

static size_t env_join(uint8_t *buf, size_t cap);
static size_t env_offer(uint8_t *buf, size_t cap);

static void setup(void)
{
    static uint8_t buf[6000];
    gz_lobby_crypto_t hc, mc;
    gz_ports_t ports;
    gz_lobby_input_t in;
    gz_lobby_host_config_t cfg;
    gz_lobby_conditions_t cond = lt_cond_fits();
    size_t n;
    if (ready_) return;
    lt_key(&HOST.key[1], "host"); lt_key(&HOST.key[3], "host factory");
    lt_key(&MEM.key[2], "member 1 contribution"); lt_key(&MEM.key[3], "member 1 factory");
    T1N = lt_unhex(LT_T1, T1, sizeof T1);
    T2N = lt_unhex(LT_T2, T2, sizeof T2);
    lt_outer(T1, T1N, &T1O);
    gz_terms_outer_digest(T1, T1N, SCOPE);
    HL = lt_link(HOST.key[1].pub, MEM.key[2].pub);
    ML = lt_link(MEM.key[2].pub, HOST.key[1].pub);
    hc = lt_crypto(&HOST); mc = lt_crypto(&MEM);
    ports.random.fill = c_rand; ports.random.ctx = NULL;
    ports.clock.now_ms = c_now; ports.clock.ctx = NULL;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    cfg.listed = 1;
    MUST(gz_lobby_host_init(&H_NEW, &ports, &hc, NULL, &cfg) == GZ_OK);
    MUST(lt_member_init(&M_NEW, &ports, &mc, NULL, NULL, &cond, SCOPE, HOST.key[1].pub, MEM.key[2].pub, MEM.key[3].pub, 1) == GZ_OK);
    H_OPEN = H_NEW;
    lreset();
    MUST(gz_lobby_host_open(&H_OPEN, T1, T1N, T2, T2N, &L) == GZ_OK);
    lt_in(&in, GZ_LIN_CONNECTED, &HL);
    lreset();
    MUST(gz_lobby_host_handle(&H_OPEN, &in, &L) == GZ_OK);
    H_SEAT = H_OPEN;
    n = env_join(buf, sizeof buf);
    MUST(lt_in_env(&in, &HL, buf, n));
    lreset();
    MUST(gz_lobby_host_handle(&H_SEAT, &in, &L) == GZ_OK && H_SEAT.n_seats == 1);
    M_CONN = M_NEW;
    lt_in(&in, GZ_LIN_CONNECTED, &ML);
    lreset();
    MUST(gz_lobby_member_handle(&M_CONN, &in, &L) == GZ_OK);
    M_READY = M_CONN;
    n = env_offer(buf, sizeof buf);
    MUST(lt_in_env(&in, &ML, buf, n));
    lreset();
    MUST(gz_lobby_member_handle(&M_READY, &in, &L) == GZ_OK && M_READY.joined && M_READY.ready);
    ready_ = 1;
}

static int inside(const uint8_t *base, size_t n, const uint8_t *p, size_t len)
{
    return !p || (p >= base && len <= n && (size_t)(p - base) <= n - len);
}

/* 1 if every record type of a TLV stream is one the outer decoder knows. */
static int all_known(const uint8_t *b, size_t n)
{
    gz_lw_tlv_t t;
    memset(&t, 0, sizeof t);
    t.p = b; t.len = n;
    while (gz_lw_tlv_next(&t) == 1)
        if (t.type % 2 == 1 && t.type != 3 && t.type != 5) return 0;
    return 1;
}

/* A decoded message's pointers lie inside the records it was decoded from. */
static void fields_inside(const gz_lobby_msg_t *m, const uint8_t *rec, size_t n)
{
    MUST(m->records == rec && m->records_len == n && m->signed_len <= n);
    MUST(inside(rec, n, m->sig, 64) && inside(rec, n, m->outer, m->outer_len) && inside(rec, n, m->outer_sig, 64) &&
         inside(rec, n, m->current, m->current_len) && inside(rec, n, m->current_sig, 64) &&
         inside(rec, n, m->factory_key, 33) &&
         inside(rec, n, m->bind_by_contribution, 64) && inside(rec, n, m->check_id, 32) &&
         inside(rec, n, m->outer_digest, 32) && inside(rec, n, m->current_digest, 32) &&
         inside(rec, n, m->display_name, m->display_name_len));
}

/* The bytes as a record of every lobby type, and of one that is nobody's. */
static void restore_all(gz_lobby_host_t *h, gz_lobby_member_t *m, const uint8_t *x, size_t size)
{
    const gz_lobby_rec_max_t *t;
    size_t nt, i;
    gz_record_t rec;
    gz_status_t st;
    t = gz_lobby_rec_table(&nt);
    rec.bytes.data = x; rec.bytes.len = size;
    for (i = 0; i <= nt; i++) {
        rec.type = i < nt ? t[i].type : 0x0001001au;
        if (h) {
            st = gz_lobby_host_restore(h, &rec);
            MUST(st == GZ_OK || st == GZ_ERR_CORRUPT);
            MUST(i < nt || st == GZ_OK);                          /* another engine's record: skipped */
            MUST(!(i < nt && st == GZ_OK && size > t[i].max));      /* never one over its largest size */
            if (i < nt && st == GZ_OK) lobby_fuzz_stats[3]++;
        }
        if (m) {
            st = gz_lobby_member_restore(m, &rec);
            MUST(st == GZ_OK || st == GZ_ERR_CORRUPT);
            MUST(i < nt || st == GZ_OK);
            MUST(!(i < nt && st == GZ_OK && size > t[i].max));
            if (i < nt && st == GZ_OK) lobby_fuzz_stats[3]++;
        }
    }
    {   /* the node part's readers of the same bytes */
        uint8_t sc[32], state;
        uint16_t reason;
        const uint8_t *cancel;
        size_t cl;
        for (i = 0; i < nt; i++) {
            rec.type = t[i].type;
            if (gz_lobby_rec_scope(&rec, sc)) MUST(size >= 34 && size <= t[i].max);
            if (gz_lobby_rec_ended(&rec, sc, &state, &reason, &cancel, &cl))
                MUST(rec.type == GZ_REC_LOBBY_ENDED && inside(x, size, cancel, cl) && cl <= GZ_LOBBY_MAX_SAVED_MSG);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static gz_terms_outer_t o, o2;
    static gz_lobby_host_t host;
    static gz_lobby_member_t mem;
    gz_terms_current_t c;
    gz_lobby_msg_t m;
    gz_lobby_input_t in;
    uint8_t *x;
    int is_env, pass;
    setup();
    rnd = 0x9e3779b97f4a7c15ull ^ size;
    x = malloc(size ? size : 1);                       /* exactly `size` bytes: an over-read is caught */
    MUST(x != NULL);
    if (size) memcpy(x, data, size);
    /* 1. an envelope, and its (kind, scope, records) */
    if (gz_lobby_decode_env(x, size, &m) == GZ_DEC_OK) {
        gz_lobby_msg_t m2;
        uint8_t h1[32], h2[32];
        lobby_fuzz_stats[0]++;
        MUST(size >= GZ_LOBBY_ENV_HDR);
        fields_inside(&m, x + GZ_LOBBY_ENV_HDR, size - GZ_LOBBY_ENV_HDR);
        MUST(gz_lobby_decode(m.kind, x + 6, x + GZ_LOBBY_ENV_HDR, size - GZ_LOBBY_ENV_HDR, &m2) == GZ_DEC_OK &&
             m2.kind == m.kind && m2.signed_len == m.signed_len && memcmp(m2.scope, m.scope, 32) == 0);
        gz_lobby_msg_hash(&m, h1);
        gz_lobby_msg_hash(&m2, h2);
        MUST(memcmp(h1, h2, 32) == 0);
    }
    /* the bytes as records alone, under the kind their first two bytes name */
    if (size >= 2) {
        int code = gz_lobby_decode((uint16_t)(x[0] << 8 | x[1]), SCOPE, x + 2, size - 2, &m);
        MUST(code >= GZ_DEC_OK && code <= GZ_DEC_REFUSE && code != GZ_DEC_BADTAG);
        if (code == GZ_DEC_OK) fields_inside(&m, x + 2, size - 2);
    }
    /* 2. both terms records */
    if (lt_outer(x, size, &o)) {                      /* core/tree's decoder, the lobby's policy */
        static uint8_t again[GZ_TERMS_OUTER_MAX];
        size_t an = gz_terms_encode_outer(&o, again, sizeof again);
        lobby_fuzz_stats[1]++;
        MUST(!all_known(x, size) || (an == size && memcmp(again, x, size) == 0));
        MUST(lt_outer(x, size, &o2) && gz_terms_outer_equal(&o, &o2));
    }
    if (lt_current(x, size, &T1O, SCOPE, &c)) {
        uint8_t again[GZ_TERMS_CURRENT_MAX];
        size_t an = gz_terms_encode_current(&c, again, sizeof again);
        lobby_fuzz_stats[2]++;
        MUST(an == size && memcmp(again, x, size) == 0);
    }
    /* 3. the bytes as a record of every type: engines as init left them, then
     * engines that hold a seat; each resumes afterwards */
    for (pass = 0; pass < 2; pass++) {
        host = pass ? H_SEAT : H_NEW;
        mem = pass ? M_READY : M_NEW;
        restore_all(&host, &mem, x, size);
        lreset();
        MUST(gz_lobby_host_resume(&host, &L) == GZ_OK);
        lreset();
        MUST(gz_lobby_member_resume(&mem, &L) == GZ_OK && L.count >= 1 && lt_is_connect(&L.slots[0], HOST.key[1].pub));
    }
    /* 4. and as a message: an envelope as it is; any bytes as records under
     * the lobby's scope and the kind their first two bytes name */
    is_env = lt_in_env(&in, &HL, x, size);
    for (pass = 0; pass < 4; pass++) {
        host = pass % 2 ? H_SEAT : H_OPEN;
        mem = pass % 2 ? M_READY : M_CONN;
        if (pass < 2) {
            if (!is_env) continue;
            lt_in_env(&in, &HL, x, size);
        } else {
            if (size < 2) continue;
            lt_in(&in, GZ_LIN_MESSAGE, &HL);
            in.msg_kind = (uint16_t)(x[0] << 8 | x[1]);
            in.scope = SCOPE;
            in.records = x + 2;
            in.len = size - 2;
        }
        lreset();
        MUST(gz_lobby_host_handle(&host, &in, &L) == GZ_OK);
        lreset();
        MUST(gz_lobby_host_listing(&host, &in.link, &L) == GZ_OK);
        in.link = ML;
        lreset();
        MUST(gz_lobby_member_handle(&mem, &in, &L) == GZ_OK);
    }
    free(x);
    return 0;
}

/* ---- valid inputs to start from ---------------------------------------- */

static size_t env_offer(uint8_t *buf, size_t cap)
{
    gz_lobby_enc_t e;
    uint8_t cd[32], s1[64], s2[64];
    gz_terms_current_digest(T2, T2N, cd);
    lt_sign(&HOST, 1, SCOPE, s1); lt_sign(&HOST, 1, cd, s2);
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_TERMS_OFFER, SCOPE);
    gz_lobby_enc_record(&e, 2, T1, T1N); gz_lobby_enc_record(&e, 4, s1, 64);
    gz_lobby_enc_record(&e, 6, T2, T2N); gz_lobby_enc_record(&e, 8, s2, 64);
    return gz_lobby_enc_done(&e);
}

static size_t env_join(uint8_t *buf, size_t cap)
{
    gz_lobby_enc_t e;
    /* K1: a join carries no factory key and no binding, only the optional name */
    gz_lobby_enc_start(&e, buf, cap, GZ_KIND_JOIN, SCOPE);
    gz_lobby_enc_record(&e, 7, (const uint8_t *)"name", 4);
    return gz_lobby_enc_done(&e);
}

/* T1, T2, one message of every lobby kind as an envelope (the signed ones
 * signed), and one record of every type, each as its engine reads it. */
void lobby_fuzz_corpus(void (*add)(const uint8_t *b, size_t n))
{
    static uint8_t buf[6000], rec[6000], ready[300], check[300], start[300], cancel[300], join[400], list[400];
    gz_lobby_enc_t e;
    gz_lobby_crypto_t hc, mc;
    gz_lr_t w;
    uint8_t cd[32], s1[64], s2[64], b[32], sc[64], ev[200];
    size_t rn, kn, sn, cn, jn, ln;
    setup();
    hc = lt_crypto(&HOST); mc = lt_crypto(&MEM);
    gz_terms_current_digest(T2, T2N, cd);
    lt_sign(&HOST, 1, SCOPE, s1); lt_sign(&HOST, 1, cd, s2);
    gz_lobby_binding(SCOPE, MEM.key[3].pub, MEM.key[2].pub, b);
    lt_sign(&MEM, 2, b, sc);                              /* K1: the contribution key's binding only */
    /* the terms records and the messages: 12 inputs */
    add(T1, T1N); add(T2, T2N);
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, SCOPE); add(buf, gz_lobby_enc_done(&e));
    add(buf, env_offer(buf, sizeof buf));
    jn = env_join(join, sizeof join); add(join, jn);
    gz_lobby_enc_start(&e, ready, sizeof ready, GZ_KIND_READY, SCOPE);
    gz_lobby_enc_record(&e, 2, SCOPE, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd, 32);
    gz_lobby_enc_record(&e, 8, cd, 32); gz_lobby_enc_u16(&e, 11, 3);
    gz_lobby_enc_record(&e, 12, MEM.key[3].pub, 33); gz_lobby_enc_record(&e, 14, sc, 64);   /* K1 */
    rn = gz_lobby_enc_sign(&e, &mc, 2); add(ready, rn);
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_UNREADY, SCOPE); gz_lobby_enc_u16(&e, 1, 3); add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LEAVE, SCOPE); gz_lobby_enc_u16(&e, 1, 3); add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LOBBY_STATUS, SCOPE);
    gz_lobby_enc_u8(&e, 2, 1); gz_lobby_enc_u8(&e, 4, 2); gz_lobby_enc_u32(&e, 6, 2);
    gz_lobby_enc_u16(&e, 8, 3); gz_lobby_enc_u16(&e, 10, 2); gz_lobby_enc_u16(&e, 13, 5);
    add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, check, sizeof check, GZ_KIND_READY_CHECK, SCOPE);
    gz_lobby_enc_record(&e, 2, cd, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd, 32);
    gz_lobby_enc_u32(&e, 8, 30000);
    kn = gz_lobby_enc_sign(&e, &hc, 1); add(check, kn);
    gz_lobby_enc_start(&e, start, sizeof start, GZ_KIND_START, SCOPE);
    gz_lobby_enc_record(&e, 2, cd, 32); gz_lobby_enc_u8(&e, 4, 1); gz_lobby_enc_u16(&e, 6, 4);
    sn = gz_lobby_enc_sign(&e, &hc, 1); add(start, sn);
    gz_lobby_enc_start(&e, cancel, sizeof cancel, GZ_KIND_CANCEL, SCOPE); gz_lobby_enc_u16(&e, 2, 1);
    cn = gz_lobby_enc_sign(&e, &hc, 1); add(cancel, cn);
    /* the records: 15 inputs. lobby_opened and terms_received have one layout. */
    gz_lr_start(&w, rec, sizeof rec, SCOPE);
    gz_lr_put(&w, 4, T1, T1N); gz_lr_put(&w, 6, s1, 64); gz_lr_put(&w, 8, T2, T2N); gz_lr_put(&w, 10, s2, 64);
    add(rec, gz_lr_done(&w));
    gz_lr_start(&w, rec, sizeof rec, SCOPE);
    gz_lr_put(&w, 4, T2, T2N); gz_lr_put(&w, 6, s2, 64);
    add(rec, gz_lr_done(&w));                                                      /* terms_version */
    add(rec, lt_rec_seat(rec, sizeof rec, SCOPE, MEM.key[2].pub, MEM.key[3].pub, sc, GZ_SEAT_READY, 3, 1, 1, ready, rn));
    add(rec, lt_rec_seat(rec, sizeof rec, SCOPE, MEM.key[2].pub, MEM.key[3].pub, sc, GZ_SEAT_JOINED, 0, 0, 1, NULL, 0));
    add(rec, lt_rec_freeze(rec, sizeof rec, SCOPE, cd, 1, cd, check, kn));
    add(rec, lt_rec_ended(rec, sizeof rec, SCOPE, GZ_LOBBY_CANCELLED, 1, cancel, cn));
    add(rec, lt_rec_ended(rec, sizeof rec, SCOPE, 0, 2, NULL, 0));                  /* a member's own leave */
    add(rec, lt_rec_msg(rec, sizeof rec, SCOPE, join, jn));                         /* joined */
    add(rec, lt_rec_msg(rec, sizeof rec, SCOPE, ready, rn));                        /* ready_sent: a ready */
    add(rec, lt_rec_unready(rec, sizeof rec, SCOPE, 3));                            /* ready_sent: an unready */
    memcpy(ev, T2, T2N); memcpy(ev + T2N, s2, 64);
    gz_lr_start(&w, rec, sizeof rec, SCOPE);
    gz_lr_int(&w, 4, GZ_FAULT_TWO_VALUES, 1); gz_lr_put(&w, 6, ev, T2N + 64); gz_lr_put(&w, 8, ev, T2N + 64);
    add(rec, gz_lr_done(&w));                                                      /* host_fault */
    memcpy(list, MEM.key[2].pub, 33);
    gz_lw_put(list + 33, sn, 2);
    memcpy(list + 35, start, sn);
    ln = 35 + sn;
    gz_lr_start(&w, rec, sizeof rec, SCOPE);
    gz_lr_put(&w, 4, cd, 32); gz_lr_int(&w, 6, 1794441000000ull, 8); gz_lr_put(&w, 8, list, ln);
    add(rec, gz_lr_done(&w));                                                      /* start_sent */
    add(rec, lt_rec_msg(rec, sizeof rec, SCOPE, start, sn));                        /* start_received */
    add(rec, lt_rec_state(rec, sizeof rec, SCOPE, GZ_LOBBY_FUNDING, NULL));
    add(rec, lt_rec_state(rec, sizeof rec, SCOPE, GZ_LOBBY_OPEN, cd));
}
