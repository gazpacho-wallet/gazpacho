/* Fuzzing of every decoder: the envelope and every lobby message, both terms
 * records, the part reassembler, the host's and the member's record readers,
 * and both engines fed hostile bytes. Mutations of valid inputs (bit flips,
 * boundary bytes, BigSize prefixes, insertions, deletions, truncation,
 * splicing), run under the sanitizers. Properties checked beyond "no crash":
 * a decoded message's fields lie inside its bytes; an accepted terms record
 * with only known types re-encodes to exactly its bytes (one encoding per set
 * of terms); engines answer every input with GZ_OK.
 *
 * usage: fuzz_lobby ITERATIONS SEED */
#include "../check.h"
#include "lobby_test.h"
#include "rng.h"
#include "../../core/lobby/lobby_internal.h"
#include <stdlib.h>

#define MAXB 6000
typedef struct { uint8_t b[MAXB]; size_t n; } blob_t;
static blob_t corpus[32];
static int n_corpus;
static sim_rng_t R;
static lt_signer_t HOST, MEM;
static uint8_t SCOPE[32];
static gz_terms_outer_t T1O;

static void add(const uint8_t *b, size_t n) { if (n <= MAXB && n_corpus < 32) { memcpy(corpus[n_corpus].b, b, n); corpus[n_corpus++].n = n; } }

static size_t mutate(const blob_t *in, uint8_t *out)
{
    size_t n = in->n, k, rounds = 1 + sim_rng_below(&R, 4), r;
    memcpy(out, in->b, n);
    for (r = 0; r < rounds; r++) {
        size_t at = n ? (size_t)sim_rng_below(&R, n) : 0, len;
        static const uint8_t edge[] = {0x00, 0x01, 0x02, 0x20, 0x40, 0x7f, 0x80, 0xf0, 0xfc, 0xfd, 0xfe, 0xff};
        switch (sim_rng_below(&R, 8)) {
        case 0: if (n) out[at] ^= (uint8_t)(1u << sim_rng_below(&R, 8)); break;
        case 1: if (n) out[at] = edge[sim_rng_below(&R, sizeof edge)]; break;
        case 2: if (n) out[at] = (uint8_t)sim_rng_below(&R, 256); break;
        case 3: len = 1 + (size_t)sim_rng_below(&R, 8);                    /* insert */
            if (n + len < MAXB) { memmove(out + at + len, out + at, n - at); for (k = 0; k < len; k++) out[at + k] = (uint8_t)sim_rng_below(&R, 256); n += len; }
            break;
        case 4: len = 1 + (size_t)sim_rng_below(&R, 16);                   /* delete */
            if (at + len <= n) { memmove(out + at, out + at + len, n - at - len); n -= len; }
            break;
        case 5: n = at; break;                                             /* truncate */
        case 6: {                                                          /* splice */
            const blob_t *o = &corpus[sim_rng_below(&R, (uint64_t)n_corpus)];
            size_t from = o->n ? (size_t)sim_rng_below(&R, o->n) : 0;
            len = o->n - from;
            if (at + len > MAXB) len = MAXB - at;
            memcpy(out + at, o->b + from, len);
            if (at + len > n) n = at + len;
            break;
        }
        default:                                                           /* a BigSize prefix */
            if (n + 2 < MAXB) { memmove(out + at + 2, out + at, n - at); out[at] = 0xfd; out[at + 1] = 0; n += 2; }
            break;
        }
    }
    return n;
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

static uint64_t c_now(void *ctx) { (void)ctx; return 1794441000000ull; }
static void c_rand(void *ctx, uint32_t p, uint8_t *o, size_t n) { (void)ctx; (void)p; sim_rng_fill(&R, o, n); }

int main(int argc, char **argv)
{
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 20000, i;
    uint64_t seed = argc > 2 ? strtoull(argv[2], NULL, 10) : 1;
    static uint8_t buf[MAXB], t1[512], t2[128], reasm[GZ_PART_MAX_BODY];
    static gz_terms_outer_t o, o2;
    static gz_lobby_host_t host;
    static gz_lobby_member_t mem;
    static gz_part_reasm_t ra;
    static gz_action_t slots[256];
    static uint8_t abytes[1 << 18];
    gz_action_list_t l;
    gz_terms_current_t c;
    gz_lobby_msg_t m;
    gz_lobby_crypto_t hc, mc;
    gz_ports_t ports;
    gz_lobby_input_t in;
    gz_lobby_host_config_t cfg;
    gz_lobby_conditions_t cond = lt_cond_fits();
    gz_lobby_enc_t e;
    size_t t1n, t2n, n;
    unsigned long ok_msg = 0, ok_outer = 0, ok_cur = 0, ok_part = 0, engine_bad = 0, field_bad = 0, canon_bad = 0;
    uint8_t cd[32], zero[33];

    setvbuf(stdout, NULL, _IONBF, 0);
    sim_rng_init(&R, seed, 9);
    lt_key(&HOST.key[1], "host"); lt_key(&HOST.key[3], "host factory");
    lt_key(&MEM.key[2], "member 1 contribution"); lt_key(&MEM.key[3], "member 1 factory");
    hc = lt_crypto(&HOST); mc = lt_crypto(&MEM);
    t1n = lt_unhex(LT_T1, t1, sizeof t1);
    t2n = lt_unhex(LT_T2, t2, sizeof t2);
    gz_terms_outer_decode(t1, t1n, &T1O);
    gz_terms_outer_digest(t1, t1n, SCOPE);
    gz_terms_current_digest(t2, t2n, cd);
    memset(zero, 0, sizeof zero);
    add(t1, t1n); add(t2, t2n);
    /* one message of every lobby kind, and a part */
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_HELLO, SCOPE); add(buf, gz_lobby_enc_done(&e));
    {
        uint8_t s1[64], s2[64];
        lt_sign(&HOST, 1, SCOPE, s1); lt_sign(&HOST, 1, cd, s2);
        gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_TERMS_OFFER, SCOPE);
        gz_lobby_enc_record(&e, 2, t1, t1n); gz_lobby_enc_record(&e, 4, s1, 64);
        gz_lobby_enc_record(&e, 6, t2, t2n); gz_lobby_enc_record(&e, 8, s2, 64);
        add(buf, gz_lobby_enc_done(&e));
    }
    {
        uint8_t b[32], sf[64], sc[64];
        gz_lobby_binding(SCOPE, MEM.key[3].pub, MEM.key[2].pub, b);
        lt_sign(&MEM, 3, b, sf); lt_sign(&MEM, 2, b, sc);
        gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_JOIN, SCOPE);
        gz_lobby_enc_record(&e, 2, MEM.key[3].pub, 33); gz_lobby_enc_record(&e, 4, sf, 64);
        gz_lobby_enc_record(&e, 6, sc, 64); gz_lobby_enc_record(&e, 7, (const uint8_t *)"name", 4);
        add(buf, gz_lobby_enc_done(&e));
    }
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_READY, SCOPE);
    gz_lobby_enc_record(&e, 2, SCOPE, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd, 32);
    gz_lobby_enc_record(&e, 8, cd, 32); gz_lobby_enc_u16(&e, 11, 3);
    add(buf, gz_lobby_enc_sign(&e, &mc, 2));
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_UNREADY, SCOPE); gz_lobby_enc_u16(&e, 1, 1); add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_LEAVE, SCOPE); gz_lobby_enc_u16(&e, 1, 3); add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_LOBBY_STATUS, SCOPE);
    gz_lobby_enc_u8(&e, 2, 1); gz_lobby_enc_u8(&e, 4, 2); gz_lobby_enc_u32(&e, 6, 2);
    gz_lobby_enc_u16(&e, 8, 3); gz_lobby_enc_u16(&e, 10, 2); gz_lobby_enc_u16(&e, 13, 5);
    add(buf, gz_lobby_enc_done(&e));
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_READY_CHECK, SCOPE);
    gz_lobby_enc_record(&e, 2, cd, 32); gz_lobby_enc_u32(&e, 4, 1); gz_lobby_enc_record(&e, 6, cd, 32);
    gz_lobby_enc_u32(&e, 8, 30000); add(buf, gz_lobby_enc_sign(&e, &hc, 1));
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_START, SCOPE);
    gz_lobby_enc_record(&e, 2, cd, 32); gz_lobby_enc_u8(&e, 4, 1); gz_lobby_enc_u16(&e, 6, 4);
    add(buf, gz_lobby_enc_sign(&e, &hc, 1));
    gz_lobby_enc_start(&e, buf, MAXB, GZ_KIND_CANCEL, SCOPE); gz_lobby_enc_u16(&e, 2, 1); add(buf, gz_lobby_enc_sign(&e, &hc, 1));
    {
        static uint8_t body[70000], p[66000];
        size_t k, pn;
        for (k = 0; k < sizeof body; k++) body[k] = (uint8_t)k;
        pn = gz_part_build(68, SCOPE, body, sizeof body, 1, p, sizeof p);
        add(p, pn);
    }
    printf("fuzz: corpus of %d inputs\n", n_corpus);

    ports.random.fill = c_rand; ports.random.ctx = NULL;
    ports.clock.now_ms = c_now; ports.clock.ctx = NULL;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.factory_key, HOST.key[3].pub, 33);
    gz_part_reasm_init(&ra, reasm, sizeof reasm);

    for (i = 0; i < iters; i++) {
        const blob_t *src = &corpus[sim_rng_below(&R, (uint64_t)n_corpus)];
        gz_status_t st;
        gz_record_t rec;
        uint8_t *x;
        n = mutate(src, buf);
        x = malloc(n ? n : 1);              /* exactly n bytes: an over-read is caught */
        memcpy(x, buf, n);
        /* 1. the envelope and every lobby message */
        if (gz_lobby_decode(x, n, &m) == GZ_DEC_OK) {
            ok_msg++;
            if (!inside(x, n, m.sig, 64) || !inside(x, n, m.outer, m.outer_len) || !inside(x, n, m.current, m.current_len) ||
                !inside(x, n, m.factory_key, 33) || !inside(x, n, m.check_id, 32) || !inside(x, n, m.data, m.data_len) ||
                !inside(x, n, m.display_name, m.display_name_len) || m.signed_len > n - 2)
                field_bad++;
            if (m.kind == GZ_KIND_PART) {
                uint16_t k; uint8_t sc[32]; const uint8_t *body; size_t bl;
                if (gz_part_feed(&ra, &m, &k, sc, &body, &bl) == 1) ok_part++;
            }
        }
        /* 2. both terms records */
        if (gz_terms_outer_decode(x, n, &o)) {
            static uint8_t again[GZ_TERMS_OUTER_MAX];
            size_t an = gz_terms_outer_encode(&o, again, sizeof again);
            ok_outer++;
            if (all_known(x, n) && (an != n || memcmp(again, x, n) != 0)) canon_bad++;
            if (!gz_terms_outer_decode(x, n, &o2) || memcmp(&o, &o2, sizeof o) != 0) canon_bad++;
        }
        if (gz_terms_current_decode(x, n, &T1O, SCOPE, &c)) {
            uint8_t again[GZ_TERMS_CURRENT_MAX];
            size_t an = gz_terms_current_encode(&c, &T1O, again, sizeof again);
            ok_cur++;
            if (an != n || memcmp(again, x, n) != 0) canon_bad++;
        }
        /* 3. the record readers */
        rec.type = 0x00010002u + 2u * (uint32_t)sim_rng_below(&R, 13);
        rec.bytes.data = x; rec.bytes.len = n;
        if (i % 64 == 0) {
            gz_lobby_host_init(&host, &ports, &hc, NULL, &cfg);
            gz_lobby_member_init(&mem, &ports, &mc, NULL, &cond, SCOPE, HOST.key[1].pub, MEM.key[2].pub, MEM.key[3].pub, 1);
            gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
            gz_lobby_host_open(&host, t1, t1n, t2, t2n, &l);
            memset(&in, 0, sizeof in);
            in.kind = GZ_LIN_CONNECTED; in.peer_id = 7; in.peer_key = MEM.key[2].pub;
            gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
            gz_lobby_host_handle(&host, &in, &l);
            in.peer_id = 1; in.peer_key = HOST.key[1].pub;
            gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
            gz_lobby_member_handle(&mem, &in, &l);
        }
        st = gz_lobby_host_restore(&host, &rec);
        if (st != GZ_OK && st != GZ_ERR_CORRUPT) engine_bad++;
        st = gz_lobby_member_restore(&mem, &rec);
        if (st != GZ_OK && st != GZ_ERR_CORRUPT) engine_bad++;
        /* 4. both engines, fed the bytes as a message */
        memset(&in, 0, sizeof in);
        in.kind = GZ_LIN_MESSAGE; in.bytes = x; in.len = n;
        in.peer_id = 7;
        gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
        if (gz_lobby_host_handle(&host, &in, &l) != GZ_OK) engine_bad++;
        in.peer_id = 1;
        gz_action_list_init(&l, slots, 256, abytes, sizeof abytes);
        if (gz_lobby_member_handle(&mem, &in, &l) != GZ_OK) engine_bad++;
        free(x);
    }
    printf("fuzz: %lu inputs; accepted %lu messages, %lu outer, %lu current, %lu reassembled; "
           "%lu field, %lu encoding, %lu engine problems\n",
           iters, ok_msg, ok_outer, ok_cur, ok_part, field_bad, canon_bad, engine_bad);
    CHECK(field_bad == 0 && canon_bad == 0 && engine_bad == 0);
    CHECK(ok_msg > 0 && ok_outer > 0 && ok_cur > 0);      /* the mutations reach the accepting paths */
    return check_done();
}
