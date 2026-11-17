/* Shared helpers for the lobby tests: the crypto port over libsecp256k1 with
 * the test keys of terms.md section 11, hex, T1/T2 built in, and the adapters
 * for contract v2: links, envelopes as MESSAGE inputs, SEND actions read back
 * as envelopes, refusals (DISCONNECT), seats (SET_SEATED), and Lobby records
 * built and read through the engine's own helpers (lobby_internal.h). */
#ifndef GAZPACHO_LOBBY_TEST_H
#define GAZPACHO_LOBBY_TEST_H

#include "gazpacho/lobby.h"
#include "../../core/tree/internal.h"   /* core/tree's SHA-256 */
#include "../../core/lobby/lobby_internal.h"   /* gz_lr_*, gz_lf_*: the records' own writer and reader */
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <stdio.h>
#include <string.h>

static secp256k1_context *lt_ctx(void)
{
    static secp256k1_context *c;
    if (!c) c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return c;
}

/* A key: SHA256("gazpacho test key: <label>"), as terms.md section 11. */
typedef struct { secp256k1_keypair kp; uint8_t pub[33]; } lt_key_t;

static inline void lt_key(lt_key_t *k, const char *label)
{
    tr_sha256_t s;
    uint8_t sec[32];
    secp256k1_pubkey pk;
    size_t n = 33;
    const char *pre = "gazpacho test key: ";
    tr_sha256_init(&s);
    tr_sha256_write(&s, (const uint8_t *)pre, strlen(pre));
    tr_sha256_write(&s, (const uint8_t *)label, strlen(label));
    tr_sha256_done(&s, sec);
    if (!secp256k1_keypair_create(lt_ctx(), &k->kp, sec)) { printf("bad test key\n"); return; }
    if (!secp256k1_keypair_pub(lt_ctx(), &pk, &k->kp)) return;
    secp256k1_ec_pubkey_serialize(lt_ctx(), k->pub, &n, &pk, SECP256K1_EC_COMPRESSED);
}

/* One party's keys behind the port: host, contribution, factory. */
typedef struct { lt_key_t key[4]; int fail_sign; unsigned long signs, verifies; } lt_signer_t;

static inline int lt_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64])
{
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey x;
    if (ctx) ((lt_signer_t *)ctx)->verifies++;
    if (!secp256k1_ec_pubkey_parse(lt_ctx(), &pk, pub, 33)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(lt_ctx(), &x, NULL, &pk)) return 0;
    return secp256k1_schnorrsig_verify(lt_ctx(), sig, msg, 32, &x);
}

static inline int lt_point_ok(void *ctx, const uint8_t pub[33])
{
    secp256k1_pubkey pk;
    (void)ctx;
    return secp256k1_ec_pubkey_parse(lt_ctx(), &pk, pub, 33);
}

static inline int lt_sign(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64])
{
    lt_signer_t *s = ctx;
    static const uint8_t aux[32];
    if (which < 1 || which > 3 || s->fail_sign) return 0;
    s->signs++;
    return secp256k1_schnorrsig_sign32(lt_ctx(), sig, msg, &s->key[which].kp, aux);
}

static inline gz_lobby_crypto_t lt_crypto(lt_signer_t *s)
{
    gz_lobby_crypto_t c;
    c.verify = lt_verify;
    c.point_ok = lt_point_ok;
    c.sign = lt_sign;
    c.ctx = s;
    return c;
}

static inline size_t lt_unhex(const char *h, uint8_t *out, size_t cap)
{
    size_t n = 0;
    unsigned v;
    while (*h) {
        if (*h == ' ' || *h == '\n') { h++; continue; }
        if (n >= cap || sscanf(h, "%2x", &v) != 1) return 0;
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static const char LT_T1[] =
    "0220f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e97398810800"
    "0000042102b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e"
    "34733491560610c31b4b333d598e176bb883203548a5e60801020a0200080c02"
    "00030e08000000006af501801001001204000075301404000927c016040000ea"
    "6018090004000300100104031a04000000901c04000000241e08000000000001"
    "86a02004000000642201004010000000000000000000000000000007d0421000"
    "0000000000000000000000000003e84410000000000000006400000000000009"
    "c4";
static const char LT_T2[] =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000001400800000000000001f4420800000000000003e844080000"
    "0000000003e8";
static const char LT_T3[] =
    "022075e970b6d95c7de97bf35f67033e2c9f55de1ea54beecb8431419659f0a4"
    "24f2040400000002400800000000000005dc420800000000000003e844080000"
    "0000000003e8";

/* A member's conditions that T1 fits as a whole: core/tree's limits, the
 * three adjustable types listed in order (LT_ADJ(c, k) is type 64 + 2k). */
static inline gz_lobby_conditions_t lt_cond_fits(void)
{
    gz_lobby_conditions_t c;
    memset(&c, 0, sizeof c);
    c.limits.profiles = 1u << 2;
    c.limits.min_lifetime = 1; c.limits.max_lifetime = 52560; c.limits.max_tree_feerate = 1000000;
    c.limits.min_channel_sat = 100000;
    c.limits.n_max = 3;
    c.limits.max[0].type = 64; c.limits.max[0].max = 2000;
    c.limits.max[1].type = 66; c.limits.max[1].max = 1000;
    c.limits.max[2].type = 68; c.limits.max[2].max = 2500;
    return c;
}
#define LT_ADJ(c, k) ((c).limits.max[k].max)

/* Decode a record the tests built themselves, under the lobby's policy. */
static inline int lt_outer(const uint8_t *b, size_t n, gz_terms_outer_t *o)
{
    return gz_terms_decode_outer(b, n, gz_lobby_policy(), o) == GZ_TERMS_OK;
}
static inline int lt_current(const uint8_t *b, size_t n, const gz_terms_outer_t *o, const uint8_t od[32],
                             gz_terms_current_t *c)
{
    return gz_terms_decode_current(b, n, o, c) == GZ_TERMS_OK && memcmp(c->outer_digest, od, 32) == 0;
}

/* ------------------------------------------------ contract v2 adapters */

/* A link: (our key, the peer's key). The host speaks to a member on
 * (host key, the member's contribution key), a member to its host on
 * (its contribution key, the pinned host key). */
static inline gz_link_t lt_link(const uint8_t local[33], const uint8_t remote[33])
{
    gz_link_t l;
    memset(&l, 0, sizeof l);
    memcpy(l.local.key, local, 33);
    memcpy(l.remote.key, remote, 33);
    return l;
}

/* CONNECTED, DISCONNECTED or TIMER on `l` (NULL: no link). */
static inline void lt_in(gz_lobby_input_t *in, int kind, const gz_link_t *l)
{
    memset(in, 0, sizeof *in);
    in->kind = kind;
    if (l) in->link = *l;
}

static const uint8_t LT_TAG[4] = {0x67, 0x7a, 0x66, 0x01};

/* An envelope (tag, kind, scope, records) as a MESSAGE input on `l`: what
 * the transport hands the engine once it has taken the tag off. 0 if `env`
 * is no envelope (too short, or another tag): the transport never passes
 * such bytes on. `in` points into `env`. */
static inline int lt_in_env(gz_lobby_input_t *in, const gz_link_t *l, const uint8_t *env, size_t n)
{
    lt_in(in, GZ_LIN_MESSAGE, l);
    if (!env || n < GZ_LOBBY_ENV_HDR || memcmp(env, LT_TAG, 4) != 0) return 0;
    in->msg_kind = (uint16_t)(env[4] << 8 | env[5]);
    in->scope = env + 6;
    in->records = env + GZ_LOBBY_ENV_HDR;
    in->len = n - GZ_LOBBY_ENV_HDR;
    return 1;
}

/* A SEND action as the envelope the transport puts on the wire: its length,
 * or 0 if it is no SEND or does not fit. */
static inline size_t lt_send_env(const gz_action_t *a, uint8_t *out, size_t cap)
{
    gz_lobby_enc_t e;
    if (a->kind != GZ_ACTION_SEND || cap < GZ_LOBBY_ENV_HDR || a->u.send.records.len > cap - GZ_LOBBY_ENV_HDR) return 0;
    gz_lobby_enc_start(&e, out, cap, a->u.send.kind, a->u.send.scope);
    if (a->u.send.records.len) memcpy(out + GZ_LOBBY_ENV_HDR, a->u.send.records.data, a->u.send.records.len);
    return GZ_LOBBY_ENV_HDR + a->u.send.records.len;
}

/* Decode a SEND action: GZ_DEC_OK and `m` filled (pointing into the action),
 * or another code; -1 if it is no SEND. */
static inline int lt_send_decode(const gz_action_t *a, gz_lobby_msg_t *m)
{
    if (a->kind != GZ_ACTION_SEND) return -1;
    return gz_lobby_decode(a->u.send.kind, a->u.send.scope, a->u.send.records.data, a->u.send.records.len, m);
}

/* 1 if `a` refuses a peer: DISCONNECT with why REFUSED, on the link whose
 * remote key is `key` (NULL: any). */
static inline int lt_is_refusal(const gz_action_t *a, const uint8_t *key)
{
    return a->kind == GZ_ACTION_DISCONNECT && a->u.disconnect.why == GZ_DISCONNECT_REFUSED &&
           (!key || memcmp(a->u.disconnect.link.remote.key, key, 33) == 0);
}

/* 1 if `a` is SET_SEATED for `key` (NULL: any) with `seated` (-1: either). */
static inline int lt_is_seated(const gz_action_t *a, const uint8_t *key, int seated)
{
    return a->kind == GZ_ACTION_SET_SEATED && (!key || memcmp(a->u.set_seated.member.key, key, 33) == 0) &&
           (seated < 0 || a->u.set_seated.seated == seated);
}

/* The member's slot in the tests: where its host is, and which key it uses. */
#define LT_ADDRESS "127.0.0.1:9735"
#define LT_KEY_EPOCH 3u
#define LT_KEY_INDEX 7u

static inline gz_lobby_member_config_t lt_member_cfg(const uint8_t scope[32], const uint8_t host_key[33],
                                                     const uint8_t ckey[33], const uint8_t fkey[33], int auto_join)
{
    gz_lobby_member_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.scope, scope, 32);
    memcpy(cfg.host_key, host_key, 33);
    memcpy(cfg.ckey, ckey, 33);
    memcpy(cfg.factory_key, fkey, 33);
    memcpy(cfg.address, LT_ADDRESS, sizeof LT_ADDRESS - 1);
    cfg.address_len = (uint8_t)(sizeof LT_ADDRESS - 1);
    cfg.key_epoch = LT_KEY_EPOCH;
    cfg.key_index = LT_KEY_INDEX;
    cfg.auto_join = auto_join;
    return cfg;
}

/* gz_lobby_member_init with the test slot (the argument order the tests had
 * before contract v2, the gate added). */
static inline gz_status_t lt_member_init(gz_lobby_member_t *m, const gz_ports_t *ports, const gz_lobby_crypto_t *crypto,
                                         const gz_lobby_signing_t *signing, const gz_lobby_gate_t *gate,
                                         const gz_lobby_conditions_t *cond, const uint8_t scope[32],
                                         const uint8_t host_key[33], const uint8_t ckey[33], const uint8_t fkey[33],
                                         int auto_join)
{
    gz_lobby_member_config_t cfg = lt_member_cfg(scope, host_key, ckey, fkey, auto_join);
    return gz_lobby_member_init(m, ports, crypto, signing, gate, cond, &cfg);
}

/* 1 if `a` is the member's CONNECT of the test slot to `host_key`. */
static inline int lt_is_connect(const gz_action_t *a, const uint8_t host_key[33])
{
    return a->kind == GZ_ACTION_CONNECT && memcmp(a->u.connect.host.key, host_key, 33) == 0 &&
           a->u.connect.address.len == sizeof LT_ADDRESS - 1 &&
           memcmp(a->u.connect.address.data, LT_ADDRESS, sizeof LT_ADDRESS - 1) == 0 &&
           a->u.connect.key_epoch == LT_KEY_EPOCH && a->u.connect.key_index == LT_KEY_INDEX;
}

/* --------------------------------------------------------------- records */

/* 1 if a saved record is one of the lobby's and no larger than its row of
 * the table of largest records (lobby.h). */
static inline int lt_rec_fits(uint32_t type, size_t len)
{
    uint32_t max = gz_lobby_rec_max(type);
    return max != 0 && len <= max;
}

/* Field `type` of a record: 1 and set, or 0 (absent, or no Lobby record). */
static inline int lt_rec_field(const uint8_t *p, size_t len, unsigned type, const uint8_t **v, size_t *n)
{
    gz_lf_t f;
    if (!gz_lf_read(p, len, NULL, &f) || type > GZ_LF_MAX || !f.v[type / 2]) return 0;
    *v = f.v[type / 2];
    *n = f.n[type / 2];
    return 1;
}

/* The record again with field `type` set to (v, n), or left out (v NULL);
 * type 2 changes the scope. Its length, 0 if it does not fit or `p` is no
 * Lobby record. Odd fields are dropped. */
static inline size_t lt_rec_with(const uint8_t *p, size_t len, unsigned type, const uint8_t *v, size_t n, uint8_t *out,
                                 size_t cap)
{
    gz_lf_t f;
    gz_lr_t w;
    unsigned t;
    if (!gz_lf_read(p, len, NULL, &f)) return 0;
    gz_lr_start(&w, out, cap, type == 2 && v ? v : f.v[1]);
    for (t = 4; t <= GZ_LF_MAX; t += 2) {
        if (t == type) { if (v) gz_lr_put(&w, t, v, n); }
        else if (f.v[t / 2]) gz_lr_put(&w, t, f.v[t / 2], f.n[t / 2]);
    }
    return gz_lr_done(&w);
}

/* A record whose only field after the scope is 4 = `msg`: JOINED, READY_SENT
 * (a ready), START_RECEIVED. */
static inline size_t lt_rec_msg(uint8_t *out, size_t cap, const uint8_t scope[32], const uint8_t *msg, size_t n)
{
    gz_lr_t w;
    gz_lr_start(&w, out, cap, scope);
    gz_lr_put(&w, 4, msg, n);
    return gz_lr_done(&w);
}

/* READY_SENT for an unready: 6 = its reason. */
static inline size_t lt_rec_unready(uint8_t *out, size_t cap, const uint8_t scope[32], uint16_t reason)
{
    gz_lr_t w;
    gz_lr_start(&w, out, cap, scope);
    gz_lr_int(&w, 6, reason, 2);
    return gz_lr_done(&w);
}

/* LOBBY_STATE: 4 = state, and 6 = the spent check (NULL: none). */
static inline size_t lt_rec_state(uint8_t *out, size_t cap, const uint8_t scope[32], uint8_t state,
                                  const uint8_t *check)
{
    gz_lr_t w;
    gz_lr_start(&w, out, cap, scope);
    gz_lr_int(&w, 4, state, 1);
    if (check) gz_lr_put(&w, 6, check, 32);
    return gz_lr_done(&w);
}

/* LOBBY_ENDED: 4 = state, 6 = reason, 8 = the cancel (n 0: none). */
static inline size_t lt_rec_ended(uint8_t *out, size_t cap, const uint8_t scope[32], uint8_t state, uint16_t reason,
                                  const uint8_t *cancel, size_t n)
{
    gz_lr_t w;
    gz_lr_start(&w, out, cap, scope);
    gz_lr_int(&w, 4, state, 1);
    gz_lr_int(&w, 6, reason, 2);
    if (n) gz_lr_put(&w, 8, cancel, n);
    return gz_lr_done(&w);
}

/* FREEZE: 4 check_id, 6 version, 8 digest, 10 the ready_check. */
static inline size_t lt_rec_freeze(uint8_t *out, size_t cap, const uint8_t scope[32], const uint8_t check[32],
                                   uint32_t version, const uint8_t digest[32], const uint8_t *msg, size_t n)
{
    gz_lr_t w;
    gz_lr_start(&w, out, cap, scope);
    gz_lr_put(&w, 4, check, 32);
    gz_lr_int(&w, 6, version, 4);
    gz_lr_put(&w, 8, digest, 32);
    gz_lr_put(&w, 10, msg, n);
    return gz_lr_done(&w);
}

/* SEAT, every field: 20 (the seat's latest ready) only if ready_len > 0. */
static inline size_t lt_rec_seat(uint8_t *out, size_t cap, const uint8_t scope[32], const uint8_t ckey[33],
                                 const uint8_t fkey[33], const uint8_t bind_f[64], const uint8_t bind_c[64],
                                 uint8_t state, uint16_t min_members, uint32_t ready_version, uint64_t join_seq,
                                 const uint8_t *ready, size_t ready_len)
{
    gz_lr_t w;
    gz_lr_start(&w, out, cap, scope);
    gz_lr_put(&w, 4, ckey, 33);
    gz_lr_put(&w, 6, fkey, 33);
    gz_lr_put(&w, 8, bind_f, 64);
    gz_lr_put(&w, 10, bind_c, 64);
    gz_lr_int(&w, 12, state, 1);
    gz_lr_int(&w, 14, min_members, 2);
    gz_lr_int(&w, 16, ready_version, 4);
    gz_lr_int(&w, 18, join_seq, 8);
    if (ready_len) gz_lr_put(&w, 20, ready, ready_len);
    return gz_lr_done(&w);
}

/* 1 if a FREEZE record of `scope` is well formed and names its own check. */
static inline int lt_freeze_ok(const uint8_t *p, size_t len, const uint8_t scope[32])
{
    gz_lf_t f;
    return gz_lf_read(p, len, scope, &f) && gz_la_freeze_ok(&f);
}

#endif
