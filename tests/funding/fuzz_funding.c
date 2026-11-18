/* Fuzz target for every decoder of the funding engine: the three records at
 * load (hostile journal bytes: only GZ_OK or GZ_ERR_CORRUPT), then commands,
 * chain events and broadcast results at handle (only GZ_OK), and the
 * transaction walker (gz_fund_tx_vsize, gz_fund_tx_strip). Every step stays
 * within the declared worst step. A seed of valid records is mixed in so
 * that the decoders' later checks are reached. */
#include "fund_test.h"

static ft_t *T_host, *T_member, *S_host, *S_member;
static int g_corrupt;
static uint8_t mut[GZ_FUND_MAX_SIGNED + 64];

/* Seed journals with every record kind: a host funding, its abandonment and
 * spend-back; a member's first status. */
static void seeds(void)
{
    gz_fund_plan_in_t in;
    gz_fund_plan_out_t res;
    gz_fund_h1_in_t h;
    uint8_t acked[1] = { 1 }, sig[1] = { 1 }, prop[GZ_FUND_MAX_TX], tx[200];
    gz_event_t e;
    S_host = ft_new(1, GZ_HOST_FUNDING_AUTO);
    S_member = ft_new(0, GZ_HOST_FUNDING_AUTO);
    e = ev_tip(10);
    ft_ev(S_host, &e);
    memset(&in, 0, sizeof in);
    memset(in.scope, 1, 32);
    in.amount = 100000;
    ft_script(in.script, 0x77);
    ft_reset(S_host);
    gz_fund_host_plan(&S_host->f, &in, &S_host->out, &res);
    ft_after(S_host);
    memcpy(prop, res.tx, res.tx_len);
    memset(&h, 0, sizeof h);
    memcpy(h.scope, in.scope, 32);
    h.n_members = 1; h.acked = acked; h.n_nodes = 1; h.signed_ok = sig;
    h.proposed_tx = prop; h.proposed_len = res.tx_len;
    gz_fund_host_h1(&S_host->f, &h);
    ft_reset(S_host);
    gz_fund_host_apply(&S_host->f, in.scope, &S_host->out);
    ft_after(S_host);
    e = ev_tip(60);
    ft_ev(S_host, &e);
    e = ev_tick();
    ft_ev(S_host, &e);
    {
        gz_fund_acked_in_t a;
        ft_in_t ins[1];
        uint64_t amt = 5000;
        uint8_t scr[1][34];
        memset(&a, 0, sizeof a);
        ft_op(ins[0].op, 3, 0);
        ft_script(scr[0], 0x77);
        a.funding_tx_len = ft_tx(tx, ins, 1, &amt, (const uint8_t(*)[34])scr, 1, 0);
        a.funding_tx = tx;
        gz_tx_txid(tx, a.funding_tx_len, a.funding.txid);
        a.amount = 5000;
        memcpy(a.script, scr[0], 34);
        a.exit = gz_exit_signet();
        a.deadline_blocks = 36;
        ft_reset(S_member);
        gz_fund_member_acked(&S_member->f, &a, &S_member->out);
        ft_after(S_member);
    }
}

/* A seed record with a few bytes changed, loaded. */
static void op_mutated(ft_t *t, ft_t *seed, const uint8_t *d, size_t n)
{
    gz_record_t r;
    gz_batch_id_t b = { 1, 1 };
    gz_status_t st;
    if (n < 1 || seed->jn == 0) return;
    r = seed->jrec[d[0] % seed->jn];
    if (r.bytes.len > sizeof mut) return;
    memcpy(mut, r.bytes.data, r.bytes.len);
    for (size_t i = 1; i + 2 < n; i += 3) {
        size_t pos = ((size_t)d[i] << 8 | d[i + 1]) % (r.bytes.len ? r.bytes.len : 1);
        if (r.bytes.len) mut[pos] ^= d[i + 2];
    }
    if (n % 7 == 0 && r.bytes.len) r.bytes.len -= d[0] % r.bytes.len;   /* cut short */
    r.bytes.data = mut;
    st = gz_fund_load(&t->f, &r, b);
    if (st != GZ_OK && st != GZ_ERR_CORRUPT) abort();
    if (st == GZ_ERR_CORRUPT) g_corrupt = 1;
}

static void op_load(ft_t *t, const uint8_t *d, size_t n)
{
    static const uint32_t types[] = { GZ_FUND_REC_PLAN, GZ_FUND_REC_SIGNED, GZ_FUND_REC_STATUS, 0x00030008u };
    gz_record_t r;
    gz_batch_id_t b = { 1, 1 };
    gz_status_t st;
    if (n < 1) return;
    r.type = types[d[0] % 4];
    r.bytes.data = d + 1;
    r.bytes.len = n - 1;
    st = gz_fund_load(&t->f, &r, b);
    if (st != GZ_OK && st != GZ_ERR_CORRUPT) abort();
    if (st == GZ_ERR_CORRUPT) g_corrupt = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    ft_t *t;
    size_t at = 1;
    uint64_t vs;
    size_t base, sl;
    static uint8_t strip[GZ_FUND_MAX_SIGNED];
    if (!T_host) {
        T_host = ft_new(1, GZ_HOST_FUNDING_AUTO);
        T_member = ft_new(0, GZ_HOST_FUNDING_AUTO);
        seeds();
    }
    if (n < 1) return 0;
    /* The walker on the whole input. */
    if (gz_fund_tx_vsize(d, n, &vs, &base)) {
        if (base > n || vs > n) abort();
        if (!gz_fund_tx_strip(d, n, strip, sizeof strip, &sl) || sl != base) abort();
    }
    t = d[0] & 1 ? T_host : T_member;
    /* A fresh engine for each input. */
    {
        gz_ports_t p = ft_ports();
        ft_cfg(t, d[0] & 1, d[0] & 2 ? GZ_HOST_FUNDING_CONFIRM : GZ_HOST_FUNDING_AUTO);
        memset(&t->w, 0, sizeof t->w);
        memset(&t->h, 0, sizeof t->h);
        if (gz_fund_init(&t->f, &t->cfg, &p) != GZ_OK) abort();
        t->jn = 0;
        t->jat = 0;
    }
    g_corrupt = 0;
    while (at + 2 <= n && !g_corrupt) {
        uint8_t kind = d[at];
        size_t len = d[at + 1];
        const uint8_t *p = d + at + 2;
        if (len > n - at - 2) len = n - at - 2;
        at += 2 + len;
        if (kind < 0x20) {
            op_load(t, p, len);
        } else if (kind < 0x40) {
            /* Whole seed journals first, then a mutated record. */
            ft_t *seed = t == T_host ? S_host : S_member;
            gz_batch_id_t b = { 1, 1 };
            if (kind & 1)
                for (size_t k = 0; k + 1 < seed->jn; k++) {
                    gz_status_t st = gz_fund_load(&t->f, &seed->jrec[k], b);
                    if (st != GZ_OK && st != GZ_ERR_CORRUPT) abort();
                    if (st == GZ_ERR_CORRUPT) g_corrupt = 1;
                }
            op_mutated(t, seed, p, len);
        } else {
            gz_event_t e;
            memset(&e, 0, sizeof e);
            if (kind < 0x60) {
                e.kind = GZ_EVENT_USER_COMMAND;
                e.u.user.bytes.data = p;
                e.u.user.bytes.len = len;
            } else if (kind < 0x78) {
                e = ev_tip(len >= 4 ? gz_get_u32(p) : (uint32_t)len);
            } else if (kind < 0x80) {
                /* the chain view's answers for a tip: mostly the current one (B12) */
                e = ev_tip_synced(len & 1 ? (len >= 4 ? gz_get_u32(p) : (uint32_t)len) : t->f.tip);
            } else if (kind < 0xa0) {
                e = ev_tick();
            } else {
                uint8_t txid[32] = { 0 };
                memcpy(txid, p, len < 32 ? len : 32);
                /* Aim at a followed factory's txid or input now and then. */
                if (len && p[0] < 0x40)
                    for (size_t k = 0; k < GZ_FUND_MAX_FACTORIES; k++)
                        if (t->f.fac[k].used) { memcpy(txid, p[0] & 1 ? t->f.fac[k].funding.txid : t->f.fac[k].in0, 32); break; }
                if (kind < 0xc0) e = ev_conf(txid, len > 32 ? p[32] % 6 : 0, 7);
                else if (kind < 0xe0) {
                    uint8_t op[36];
                    memset(op, 0, 36);
                    memcpy(op, txid, 32);
                    e = ev_spent(op, len > 33 ? p + 1 : txid, len > 34 ? p[34] % 6 : 3);
                } else if (kind < 0xf0) {
                    e = ev_bres(txid, (gz_broadcast_outcome_t)(1 + len % 3));
                } else {
                    /* a watch the chain view can never answer (G-1) */
                    uint8_t op[36];
                    memset(op, 0, 36);
                    memcpy(op, txid, 32);
                    e = len & 1 ? ev_failed_tx(txid) : ev_failed_op(op);
                }
            }
            ft_reset(t);
            if (gz_fund_handle(&t->f, &e, &t->out) != GZ_OK) abort();
            if (t->out.count > GZ_FUND_MAX_STEP_ACTIONS || t->out.used > GZ_FUND_MAX_STEP_BYTES) abort();
            if (t->f.n_watches > GZ_FUND_MAX_WATCHES) abort();
        }
    }
    if (g_corrupt) return 0; /* a corrupt journal stops the start: nothing runs after it */
    /* Whatever was loaded resumes without an error. */
    {
        int more = 1;
        for (int i = 0; i < 64 && more; i++) {
            ft_reset(t);
            if (gz_fund_resume(&t->f, &t->out, &more) != GZ_OK) abort();
        }
    }
    return 0;
}
