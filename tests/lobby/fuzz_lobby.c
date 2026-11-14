/* Fuzz target for every lobby decoder: the envelope and every lobby message,
 * both terms records, the part reassembler, the host's and the member's
 * record readers, and both engines fed the bytes as a message. Beyond "no
 * crash", each input checks: a decoded message's fields lie inside its
 * bytes; an accepted outer record with only known types, and every accepted
 * current record, re-encodes to exactly its bytes (one encoding per set of
 * terms); the record readers answer GZ_OK or GZ_ERR_CORRUPT; the engines
 * answer GZ_OK. A failed check aborts, so libFuzzer and the plain driver
 * (fuzz_lobby_main.c, docs/notes/ci.md) both report it.
 *
 * The engines are set up afresh for every input, so a finding repeats from
 * its input alone. */
#include "lobby_test.h"
#include "../../core/lobby/lobby_internal.h"
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
void lobby_fuzz_corpus(void (*add)(const uint8_t *b, size_t n));
unsigned long lobby_fuzz_stats[4];   /* accepted: messages, outer, current, reassembled */

static int ready_;
static lt_signer_t HOST, MEM;
static uint8_t SCOPE[32], T1[512], T2[128];
static size_t T1N, T2N;
static gz_terms_outer_t T1O;
static uint64_t rnd;

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

static void setup(void)
{
    if (ready_) return;
    lt_key(&HOST.key[1], "host"); lt_key(&HOST.key[3], "host factory");
    lt_key(&MEM.key[2], "member 1 contribution"); lt_key(&MEM.key[3], "member 1 factory");
    T1N = lt_unhex(LT_T1, T1, sizeof T1);
    T2N = lt_unhex(LT_T2, T2, sizeof T2);
    lt_outer(T1, T1N, &T1O);
    gz_terms_outer_digest(T1, T1N, SCOPE);
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

#define MUST(c) do { if (!(c)) { fprintf(stderr, "fuzz_lobby: %s\n", #c); abort(); } } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static gz_terms_outer_t o, o2;
    static gz_lobby_host_t host;
    static gz_lobby_member_t mem;
    static gz_part_reasm_t ra;
    static uint8_t reasm[GZ_PART_MAX_BODY];
    static gz_action_t slots[256];
    static uint8_t abytes[1 << 19];
    gz_action_list_t l;
    gz_terms_current_t c;
    gz_lobby_msg_t m;
    gz_lobby_crypto_t hc, mc;
    gz_ports_t ports;
    gz_lobby_input_t in;
    gz_lobby_host_config_t cfg;
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_record_t rec;
    gz_status_t st;
    uint8_t *x;
    setup();
    rnd = 0x9e3779b97f4a7c15ull ^ size;
    x = malloc(size ? size : 1);                       /* exactly `size` bytes: an over-read is caught */
    MUST(x != NULL);
    if (size) memcpy(x, data, size);
    /* 1. the envelope and every lobby message, and a part through a fresh reassembler */
    if (gz_lobby_decode(x, size, &m) == GZ_DEC_OK) {
        lobby_fuzz_stats[0]++;
        MUST(inside(x, size, m.sig, 64) && inside(x, size, m.outer, m.outer_len) &&
             inside(x, size, m.current, m.current_len) && inside(x, size, m.factory_key, 33) &&
             inside(x, size, m.check_id, 32) && inside(x, size, m.data, m.data_len) &&
             inside(x, size, m.display_name, m.display_name_len) && m.signed_len <= size - 2);
        if (m.kind == GZ_KIND_PART) {
            uint16_t k;
            uint8_t sc[32];
            const uint8_t *body;
            size_t bl;
            gz_part_reasm_init(&ra, reasm, sizeof reasm);
            if (gz_part_feed(&ra, &m, &k, sc, &body, &bl) == 1) lobby_fuzz_stats[3]++;
        }
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
    /* 3. both engines, set up afresh, read the bytes as a record */
    hc = lt_crypto(&HOST); mc = lt_crypto(&MEM);
    ports.random.fill = c_rand; ports.random.ctx = NULL;
    ports.clock.now_ms = c_now; ports.clock.ctx = NULL;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    gz_lobby_host_init(&host, &ports, &hc, NULL, &cfg);
    gz_lobby_member_init(&mem, &ports, &mc, NULL, &cond, SCOPE, HOST.key[1].pub, MEM.key[2].pub, MEM.key[3].pub, 1);
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    gz_lobby_host_open(&host, T1, T1N, T2, T2N, &l);
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_CONNECTED; in.peer_id = 7; in.peer_key = MEM.key[2].pub;
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    gz_lobby_host_handle(&host, &in, &l);
    in.peer_id = 1; in.peer_key = HOST.key[1].pub;
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    gz_lobby_member_handle(&mem, &in, &l);
    rec.type = 0x00010002u + 2u * (uint32_t)((size ? x[size - 1] : 0) % 13);
    rec.bytes.data = x; rec.bytes.len = size;
    st = gz_lobby_host_restore(&host, &rec);
    MUST(st == GZ_OK || st == GZ_ERR_CORRUPT);
    st = gz_lobby_member_restore(&mem, &rec);
    MUST(st == GZ_OK || st == GZ_ERR_CORRUPT);
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    MUST(gz_lobby_host_resume(&host, &l) == GZ_OK);
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    MUST(gz_lobby_member_resume(&mem, &l) == GZ_OK);
    /* 4. and as a message */
    memset(&in, 0, sizeof in);
    in.kind = GZ_LIN_MESSAGE; in.bytes = x; in.len = size;
    in.peer_id = 7;
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    MUST(gz_lobby_host_handle(&host, &in, &l) == GZ_OK);
    in.peer_id = 1;
    gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
    MUST(gz_lobby_member_handle(&mem, &in, &l) == GZ_OK);
    free(x);
    return 0;
}

/* Valid inputs to start from: T1, T2, one message of every lobby kind (the
 * signed ones signed), and a part. */
void lobby_fuzz_corpus(void (*add)(const uint8_t *b, size_t n))
{
    static uint8_t buf[70000], body[70000];
    gz_lobby_enc_t e;
    gz_lobby_crypto_t hc, mc;
    uint8_t cd[32], s1[64], s2[64], b[32], sf[64], sc[64];
    size_t k;
    setup();
    hc = lt_crypto(&HOST); mc = lt_crypto(&MEM);
    gz_terms_current_digest(T2, T2N, cd);
    add(T1, T1N); add(T2, T2N);
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_HELLO, SCOPE); add(buf, gz_lobby_enc_done(&e));
    lt_sign(&HOST, 1, SCOPE, s1); lt_sign(&HOST, 1, cd, s2);
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_TERMS_OFFER, SCOPE);
    gz_lobby_enc_record(&e, 2, T1, T1N); gz_lobby_enc_record(&e, 4, s1, 64);
    gz_lobby_enc_record(&e, 6, T2, T2N); gz_lobby_enc_record(&e, 8, s2, 64);
    add(buf, gz_lobby_enc_done(&e));
    gz_lobby_binding(SCOPE, MEM.key[3].pub, MEM.key[2].pub, b);
    lt_sign(&MEM, 3, b, sf); lt_sign(&MEM, 2, b, sc);
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_JOIN, SCOPE);
    gz_lobby_enc_record(&e, 2, MEM.key[3].pub, 33); gz_lobby_enc_record(&e, 4, sf, 64);
    gz_lobby_enc_record(&e, 6, sc, 64); gz_lobby_enc_record(&e, 7, (const uint8_t *)"name", 4);
    add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY, SCOPE);
    gz_lobby_enc_record(&e, 2, SCOPE, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd, 32);
    gz_lobby_enc_record(&e, 8, cd, 32); gz_lobby_enc_u16(&e, 11, 3);
    add(buf, gz_lobby_enc_sign(&e, &mc, 2));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_UNREADY, SCOPE); gz_lobby_enc_u16(&e, 1, 1); add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LEAVE, SCOPE); gz_lobby_enc_u16(&e, 1, 3); add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_LOBBY_STATUS, SCOPE);
    gz_lobby_enc_u8(&e, 2, 1); gz_lobby_enc_u8(&e, 4, 2); gz_lobby_enc_u32(&e, 6, 2);
    gz_lobby_enc_u16(&e, 8, 3); gz_lobby_enc_u16(&e, 10, 2); gz_lobby_enc_u16(&e, 13, 5);
    add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_READY_CHECK, SCOPE);
    gz_lobby_enc_record(&e, 2, cd, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd, 32);
    gz_lobby_enc_u32(&e, 8, 30000); add(buf, gz_lobby_enc_sign(&e, &hc, 1));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_START, SCOPE);
    gz_lobby_enc_record(&e, 2, cd, 32); gz_lobby_enc_u8(&e, 4, 1); gz_lobby_enc_u16(&e, 6, 4);
    add(buf, gz_lobby_enc_sign(&e, &hc, 1));
    gz_lobby_enc_start(&e, buf, sizeof buf, GZ_KIND_CANCEL, SCOPE); gz_lobby_enc_u16(&e, 2, 1); add(buf, gz_lobby_enc_sign(&e, &hc, 1));
    for (k = 0; k < sizeof body; k++) body[k] = (uint8_t)k;
    add(buf, gz_part_build(68, SCOPE, body, sizeof body, 1, buf, sizeof buf));
}
