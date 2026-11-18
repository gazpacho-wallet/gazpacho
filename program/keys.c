/* SPDX-License-Identifier: MIT */
/* Keys (keys.h; docs/notes/keys.md). */
#include "keys.h"

#include <string.h>

#define H GZW_HARDENED

static void set_err(gzp_keys_err_t *err, gzp_keys_why_t why, unsigned level)
{
    if (err) {
        err->why = why;
        err->level = level;
    }
}

int gzp_keys_net_level(gzw_network net, uint32_t *out)
{
    uint32_t v;
    switch (net) {
    case GZW_NET_TESTNET4: v = 1; break;
    case GZW_NET_SIGNET: v = 2; break;
    case GZW_NET_TESTNET: v = 3; break;
    case GZW_NET_REGTEST: v = 4; break;
    default: return 0; /* mainnet (reserved, never derived) and anything else */
    }
    if (out) *out = v;
    return 1;
}

/* The master key from the seed source; the seed copy is wiped here. */
static int master(const gzp_keys_t *k, gzw_xprv *m, gzp_keys_err_t *err)
{
    uint8_t seed[64];
    gzw_reason r = GZW_REASON_OK;
    int ok;
    memset(m, 0, sizeof *m);
    if (!k->src.seed || k->src.seed(k->src.ctx, seed) != 1) {
        gzw_wipe(seed, sizeof seed);
        set_err(err, GZP_KEYS_NO_SEED, 0);
        return 0;
    }
    ok = gzw_bip32_master(k->secp, seed, sizeof seed, m, &r) == 1;
    gzw_wipe(seed, sizeof seed);
    if (!ok) set_err(err, r == GZW_REASON_INVALID_CHILD ? GZP_KEYS_UNUSABLE : GZP_KEYS_INTERNAL, 0);
    return ok;
}

/* The path of a Gazpacho branch: m/254315617'/net'/branch'. One place for
 * the purpose and the network level, so that set-up checks exactly the
 * nodes the keys are derived from. */
static void branch_path(const gzp_keys_t *k, uint32_t branch, uint32_t path[3])
{
    path[0] = GZP_KEYS_PURPOSE | H;
    path[1] = k->net_level | H;
    path[2] = branch | H;
}

/* Walk path[0..n-1] from the master, step by step so that the failing level
 * is known (level 1 is path[0]). Everything but *out is wiped. */
static int walk(const gzp_keys_t *k, const uint32_t *path, size_t n, gzw_xprv *out, gzp_keys_err_t *err)
{
    gzw_reason r = GZW_REASON_OK;
    size_t i;
    if (!master(k, out, err)) return 0;
    for (i = 0; i < n; i++) {
        if (gzw_bip32_child_priv(k->secp, out, path[i], out, &r) != 1) { /* out zeroed on failure */
            set_err(err, r == GZW_REASON_INVALID_CHILD ? GZP_KEYS_INVALID_CHILD : GZP_KEYS_INTERNAL,
                    (unsigned)(i + 1));
            return 0;
        }
    }
    return 1;
}

/* The secret and compressed public key of an extended private key. */
static int keypair_out(const gzp_keys_t *k, const gzw_xprv *x, uint8_t sec[32], uint8_t pub[33], gzp_keys_err_t *err)
{
    gzw_xpub p;
    if (gzw_bip32_neuter(k->secp, x, &p) != 1) {
        set_err(err, GZP_KEYS_INTERNAL, 0);
        return 0;
    }
    if (pub) memcpy(pub, p.pubkey, 33);
    if (sec) memcpy(sec, x->key, 32);
    gzw_wipe(&p, sizeof p);
    return 1;
}

static void zero_out(uint8_t sec[32], uint8_t pub[33])
{
    if (sec) gzw_wipe(sec, 32);
    if (pub) memset(pub, 0, 33);
}

int gzp_keys_lobby_raw(const gzp_keys_t *k, uint32_t epoch, uint32_t index, uint8_t sec[32], uint8_t pub[33],
                       gzp_keys_err_t *err)
{
    uint32_t path[5];
    gzw_xprv x;
    int ok;
    set_err(err, GZP_KEYS_OK, 0);
    zero_out(sec, pub);
    if (!k || epoch >= GZP_KEYS_INDEX_LIMIT || index >= GZP_KEYS_INDEX_LIMIT) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    branch_path(k, k->lobby_branch, path);
    path[3] = epoch | H;
    path[4] = index | H;
    ok = walk(k, path, 5, &x, err) && keypair_out(k, &x, sec, pub, err);
    gzw_wipe(&x, sizeof x);
    if (!ok) zero_out(sec, pub);
    return ok;
}

int gzp_keys_lobby(const gzp_keys_t *k, uint32_t epoch, uint32_t index, uint8_t sec[32], uint8_t pub[33],
                   gzp_keys_err_t *err)
{
    if (!k || k->frozen || epoch != k->epoch) {
        zero_out(sec, pub);
        set_err(err, k ? GZP_KEYS_POLICY : GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    return gzp_keys_lobby_raw(k, epoch, index, sec, pub, err);
}

int gzp_keys_host(const gzp_keys_t *k, uint8_t sec[32], uint8_t pub[33], uint32_t *k_out, gzp_keys_err_t *err)
{
    uint32_t path[3], i;
    gzw_xprv parent, x;
    gzw_reason r = GZW_REASON_OK;
    int ok = 0;
    set_err(err, GZP_KEYS_OK, 0);
    zero_out(sec, pub);
    if (!k) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    branch_path(k, GZP_KEYS_BRANCH_HOST, path);
    if (!walk(k, path, 3, &parent, err)) {
        gzw_wipe(&parent, sizeof parent);
        return 0;
    }
    for (i = 0; i < GZP_KEYS_INDEX_LIMIT; i++) {
        if (gzw_bip32_child_priv(k->secp, &parent, i | H, &x, &r) == 1) {
            ok = keypair_out(k, &x, sec, pub, err);
            if (ok && k_out) *k_out = i;
            break;
        }
        if (r != GZW_REASON_INVALID_CHILD) { /* only BIP 32's rare case moves on to the next k */
            set_err(err, GZP_KEYS_INTERNAL, 4);
            break;
        }
    }
    if (i == GZP_KEYS_INDEX_LIMIT) set_err(err, GZP_KEYS_INVALID_CHILD, 4);
    gzw_wipe(&parent, sizeof parent);
    gzw_wipe(&x, sizeof x);
    if (!ok) zero_out(sec, pub);
    return ok;
}

int gzp_keys_init(gzp_keys_t *k, const secp256k1_context *secp, gzw_network net, const gzp_seed_source_t *src,
                  gzp_keys_err_t *err)
{
    uint32_t path[3];
    gzw_xprv m, x;
    gzw_reason r = GZW_REASON_OK;
    int ok = 0;
    if (!k) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    memset(k, 0, sizeof *k);
    set_err(err, GZP_KEYS_OK, 0);
    if (!secp || !src || !src->seed || !gzp_keys_net_level(net, &k->net_level)) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        memset(k, 0, sizeof *k);
        return 0;
    }
    k->secp = secp;
    k->wnet = net;
    k->src = *src;
    /* The three Gazpacho branches down to the level above the epoch (or k):
     * an invalid step there means the seed cannot be used (keys.md 3), for
     * either role, so the same words work as host and as member. */
    branch_path(k, GZP_KEYS_BRANCH_LOBBY, path);
    if (!walk(k, path, 3, &x, err)) goto out;
    branch_path(k, GZP_KEYS_BRANCH_HOST, path);
    gzw_wipe(&x, sizeof x);
    if (!walk(k, path, 3, &x, err)) goto out;
    branch_path(k, GZP_KEYS_BRANCH_HOST_LOBBY, path);
    gzw_wipe(&x, sizeof x);
    if (!walk(k, path, 3, &x, err)) goto out;
    /* The BIP 86 account's public key, kept for payout scripts. */
    if (!master(k, &m, err)) goto out;
    if (gzw_bip86_account_xpub(secp, &m, net, 0, &k->account, &r) != 1) {
        set_err(err, r == GZW_REASON_INVALID_CHILD ? GZP_KEYS_INVALID_CHILD : GZP_KEYS_INTERNAL, 3);
        goto out;
    }
    ok = 1;
out:
    gzw_wipe(&m, sizeof m);
    gzw_wipe(&x, sizeof x);
    if (!ok) {
        if (err && err->why == GZP_KEYS_INVALID_CHILD) err->why = GZP_KEYS_UNUSABLE;
        gzp_keys_free(k);
    }
    return ok;
}

void gzp_keys_free(gzp_keys_t *k)
{
    if (k) gzw_wipe(k, sizeof *k);
}

int gzp_keys_payout_script(const gzp_keys_t *k, uint32_t j, uint8_t spk[34], gzp_keys_err_t *err)
{
    gzw_bip86_output o;
    gzw_reason r = GZW_REASON_OK;
    set_err(err, GZP_KEYS_OK, 0);
    if (spk) memset(spk, 0, 34);
    if (!k || !spk || j >= GZP_KEYS_INDEX_LIMIT || !k->secp) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    if (gzw_bip86_output_from_xpub(k->secp, &k->account, k->wnet, 0, 0, j, &o, &r) != 1) {
        set_err(err, r == GZW_REASON_INVALID_CHILD ? GZP_KEYS_INVALID_CHILD : GZP_KEYS_INTERNAL, 5);
        return 0;
    }
    memcpy(spk, o.script_pubkey, 34);
    return 1;
}

int gzp_keys_wallet_output(const gzp_keys_t *k, uint32_t change, uint32_t j, gzw_bip86_output *out,
                           gzp_keys_err_t *err)
{
    gzw_xprv m;
    gzw_reason r = GZW_REASON_OK;
    int ok;
    set_err(err, GZP_KEYS_OK, 0);
    if (out) memset(out, 0, sizeof *out);
    if (!k || !out || change > 1 || j >= GZP_KEYS_INDEX_LIMIT) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    if (!master(k, &m, err)) return 0;
    ok = gzw_bip86_output_from_master(k->secp, &m, k->wnet, 0, change, j, out, &r) == 1;
    gzw_wipe(&m, sizeof m);
    if (!ok) set_err(err, r == GZW_REASON_INVALID_CHILD ? GZP_KEYS_INVALID_CHILD : GZP_KEYS_INTERNAL, 5);
    return ok;
}

void gzp_keys_set_epoch(gzp_keys_t *k, uint32_t epoch)
{
    k->epoch = epoch;
}

void gzp_keys_set_role(gzp_keys_t *k, int host)
{
    k->lobby_branch = host ? GZP_KEYS_BRANCH_HOST_LOBBY : GZP_KEYS_BRANCH_LOBBY;
}

void gzp_keys_freeze(gzp_keys_t *k, int frozen)
{
    k->frozen = frozen != 0;
}

static gzp_keys_scope_t *find_scope(const gzp_keys_t *k, const uint8_t scope[32])
{
    size_t i;
    for (i = 0; i < GZP_KEYS_MAX_SCOPES; i++) /* scopes are public */
        if (k->scopes[i].used && !memcmp(k->scopes[i].scope, scope, 32)) return (gzp_keys_scope_t *)&k->scopes[i];
    return NULL;
}

int gzp_keys_scope_open(gzp_keys_t *k, const uint8_t scope[32], const uint8_t digest[32], uint32_t epoch,
                        uint32_t index, gzp_keys_err_t *err)
{
    uint8_t con[32], fac[32];
    gzp_keys_scope_t *s;
    size_t i;
    int ok;
    if (!k || !scope || !digest || index >= GZP_KEYS_INDEX_LIMIT - 1) {
        set_err(err, GZP_KEYS_BAD_ARGUMENT, 0);
        return 0;
    }
    if ((s = find_scope(k, scope)) != NULL) gzw_wipe(s, sizeof *s); /* replaced: the old secrets go first */
    for (i = 0; !s && i < GZP_KEYS_MAX_SCOPES; i++)
        if (!k->scopes[i].used) s = &k->scopes[i];
    if (!s) {
        set_err(err, GZP_KEYS_FULL, 0);
        return 0;
    }
    ok = gzp_keys_lobby(k, epoch, index, con, NULL, err) && gzp_keys_lobby(k, epoch, index + 1, fac, NULL, err);
    if (ok) {
        memcpy(s->scope, scope, 32);
        memcpy(s->digest, digest, 32);
        memcpy(s->contribution, con, 32);
        memcpy(s->factory, fac, 32);
        s->used = 1;
    }
    gzw_wipe(con, sizeof con);
    gzw_wipe(fac, sizeof fac);
    return ok;
}

int gzp_keys_scoped(const gzp_keys_t *k, const uint8_t scope[32], const uint8_t digest[32], uint8_t factory[32],
                    uint8_t contribution[32])
{
    const gzp_keys_scope_t *s;
    if (factory) gzw_wipe(factory, 32);
    if (contribution) gzw_wipe(contribution, 32);
    if (!k || !scope || !digest || !factory || !contribution || !(s = find_scope(k, scope))) return 0;
    if (gzw_ct_equal(s->digest, digest, 32) != 1) return 0; /* a round under other values gets nothing */
    memcpy(factory, s->factory, 32);
    memcpy(contribution, s->contribution, 32);
    return 1;
}

void gzp_keys_forget(gzp_keys_t *k, const uint8_t scope[32])
{
    gzp_keys_scope_t *s;
    if (k && scope && (s = find_scope(k, scope)) != NULL) gzw_wipe(s, sizeof *s);
}

void gzp_keys_forget_all(gzp_keys_t *k)
{
    if (k) gzw_wipe(k->scopes, sizeof k->scopes);
}

size_t gzp_keys_scopes_held(const gzp_keys_t *k)
{
    size_t i, n = 0;
    for (i = 0; k && i < GZP_KEYS_MAX_SCOPES; i++) n += k->scopes[i].used != 0;
    return n;
}

static int unlock_seed(void *ctx, uint8_t out[64])
{
    const gzp_unlock_t *u = ctx;
    if (!u || !u->seed || u->seed(u->ctx, out) != 0) { /* -1 not unlocked, -2 storage failed */
        gzw_wipe(out, 64);
        return 0;
    }
    return 1;
}

gzp_seed_source_t gzp_keys_seed_from_unlock(const gzp_unlock_t *unlock)
{
    gzp_seed_source_t src;
    src.seed = unlock_seed;
    src.ctx = (void *)(uintptr_t)unlock;
    return src;
}

int gzp_keys_net_fn(void *ctx, uint32_t epoch, uint32_t index, uint8_t sec[32], uint8_t pub[33])
{
    return gzp_keys_lobby((const gzp_keys_t *)ctx, epoch, index, sec, pub, NULL);
}
