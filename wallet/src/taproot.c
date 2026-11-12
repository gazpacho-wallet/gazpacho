/* Single-key taproot outputs: BIP 341 tweak with no script tree, BIP 86 paths. */
#include "gazpacho/wallet_keys.h"

#include "internal.h"

#include <string.h>

#include <secp256k1_schnorrsig.h>

/* t = hash_TapTweak(P): the tagged hash of the internal key alone, because
   there is no script tree (BIP 341 "taproot_tweak_pubkey" with h empty,
   BIP 86). */
static int taptweak(const secp256k1_context *ctx,
                    const unsigned char internal_key32[32],
                    unsigned char tweak_out32[32]) {
    static const unsigned char tag[8] = {'T', 'a', 'p', 'T', 'w', 'e', 'a', 'k'};
    return secp256k1_tagged_sha256(ctx, tweak_out32, tag, sizeof(tag),
                                   internal_key32, 32);
}

int gzw_taproot_output_key(const secp256k1_context *ctx,
                           const unsigned char internal_key32[32],
                           unsigned char output_key_out32[32],
                           int *parity_out) {
    secp256k1_xonly_pubkey internal, output_xonly;
    secp256k1_pubkey output;
    unsigned char p32[32], q32[32], tweak[32];
    int parity = 0;
    int ok = 0;

    if (!output_key_out32) return 0;
    if (!ctx || !internal_key32) {
        memset(output_key_out32, 0, 32);
        return 0;
    }
    /* Work on a copy, so the output may be the same buffer as the input. */
    memcpy(p32, internal_key32, 32);
    memset(output_key_out32, 0, 32);

    /* lift_x(P): fails if the 32 bytes are not the X of a curve point. */
    if (!secp256k1_xonly_pubkey_parse(ctx, &internal, p32)) goto done;
    if (!taptweak(ctx, p32, tweak)) goto done;
    /* Q = P + t*G; fails if t is not below the order or Q is infinity. */
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &output, &internal, tweak)) goto done;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xonly, &parity, &output))
        goto done;
    if (!secp256k1_xonly_pubkey_serialize(ctx, q32, &output_xonly)) goto done;
    /* Re-check of the relation between Q, P and t (same library, so this
       guards against a slip in the calls above, not against the library). */
    if (!secp256k1_xonly_pubkey_tweak_add_check(ctx, q32, parity, &internal, tweak))
        goto done;
    memcpy(output_key_out32, q32, 32);
    if (parity_out) *parity_out = parity;
    ok = 1;

done:
    gzw_wipe(p32, sizeof(p32));
    gzw_wipe(q32, sizeof(q32));
    gzw_wipe(tweak, sizeof(tweak));
    return ok;
}

int gzw_p2tr_script_pubkey(const unsigned char output_key32[32],
                           unsigned char spk_out34[34]) {
    unsigned char key[32];

    if (!spk_out34) return 0;
    if (!output_key32) {
        memset(spk_out34, 0, 34);
        return 0;
    }
    memcpy(key, output_key32, 32); /* the buffers may overlap */
    spk_out34[0] = 0x51; /* OP_1 */
    spk_out34[1] = 0x20; /* push 32 bytes */
    memcpy(spk_out34 + 2, key, 32);
    return 1;
}

int gzw_p2tr_address(gzw_network net, const unsigned char output_key32[32],
                     char out[GZW_ADDRESS_MAX]) {
    const char *hrp = gzw_network_hrp(net);
    unsigned char back[32];

    if (!out) return 0;
    out[0] = '\0';
    if (!hrp || !output_key32) return 0;
    if (!gzw_segwit_address_encode(hrp, 1, output_key32, 32, out)) return 0;
    /* Read the address back and require the same key. */
    if (!gzw_p2tr_address_decode(net, out, back) ||
        memcmp(back, output_key32, 32) != 0) {
        memset(out, 0, GZW_ADDRESS_MAX);
        return 0;
    }
    return 1;
}

int gzw_p2tr_address_decode(gzw_network net, const char *address,
                            unsigned char output_key_out32[32]) {
    const char *hrp = gzw_network_hrp(net);
    unsigned char prog[40];
    size_t plen = 0;
    int version = -1;

    if (!output_key_out32) return 0;
    memset(output_key_out32, 0, 32);
    if (!hrp || !address) return 0;
    if (!gzw_segwit_address_decode(hrp, address, &version, prog, &plen)) return 0;
    if (version != 1 || plen != 32) return 0;
    memcpy(output_key_out32, prog, 32);
    return 1;
}

/* ---- BIP 86 --------------------------------------------------------------- */

int gzw_bip86_path(gzw_network net, uint32_t account, uint32_t change,
                   uint32_t index, uint32_t path_out[5]) {
    uint32_t coin = 0;

    if (!path_out) return 0;
    memset(path_out, 0, 5 * sizeof(uint32_t));
    if (!gzw_network_coin_type(net, &coin)) return 0;
    if (account >= GZW_HARDENED || index >= GZW_HARDENED || change > 1) return 0;

    path_out[0] = 86u | GZW_HARDENED;
    path_out[1] = coin | GZW_HARDENED;
    path_out[2] = account | GZW_HARDENED;
    path_out[3] = change;
    path_out[4] = index;
    return 1;
}

int gzw_bip86_account_xprv(const secp256k1_context *ctx, const gzw_xprv *master,
                           gzw_network net, uint32_t account, gzw_xprv *out,
                           gzw_reason *why) {
    uint32_t path[5];

    gzw_set_reason(why, GZW_REASON_BAD_ARGUMENT);
    if (!out) return 0;
    /* The account key hangs off the wallet's master key, not off any key.
       (out may be the same object as master, so it is not cleared before
       master has been read; gzw_bip32_derive_priv works on a copy.) */
    if (!ctx || !master || master->depth != 0 ||
        !gzw_bip86_path(net, account, 0, 0, path)) {
        gzw_wipe(out, sizeof(*out));
        return 0;
    }
    return gzw_bip32_derive_priv(ctx, master, path, 3, out, why);
}

int gzw_bip86_account_xpub(const secp256k1_context *ctx, const gzw_xprv *master,
                           gzw_network net, uint32_t account, gzw_xpub *out,
                           gzw_reason *why) {
    gzw_xprv acct;
    gzw_reason r = GZW_REASON_BAD_ARGUMENT;

    gzw_set_reason(why, r);
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (gzw_bip86_account_xprv(ctx, master, net, account, &acct, &r)) {
        r = gzw_bip32_neuter(ctx, &acct, out) ? GZW_REASON_OK : GZW_REASON_INTERNAL;
    }
    gzw_wipe(&acct, sizeof(acct));
    if (r != GZW_REASON_OK) memset(out, 0, sizeof(*out));
    gzw_set_reason(why, r);
    return r == GZW_REASON_OK;
}

/* Fill everything in out from a compressed public key at a known path. */
static int output_from_pubkey33(const secp256k1_context *ctx, gzw_network net,
                                const uint32_t path[5],
                                const unsigned char pubkey33[33],
                                gzw_bip86_output *out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->path, path, 5 * sizeof(uint32_t));
    /* The internal key is the X coordinate of the derived key. */
    memcpy(out->internal_key, pubkey33 + 1, 32);
    if (!gzw_taproot_output_key(ctx, out->internal_key, out->output_key, NULL) ||
        !gzw_p2tr_address(net, out->output_key, out->address) ||
        !gzw_p2tr_script_pubkey(out->output_key, out->script_pubkey)) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    return 1;
}

int gzw_bip86_output_from_xpub(const secp256k1_context *ctx,
                               const gzw_xpub *account_xpub, gzw_network net,
                               uint32_t account, uint32_t change, uint32_t index,
                               gzw_bip86_output *out, gzw_reason *why) {
    uint32_t path[5];
    gzw_xpub leaf;
    gzw_reason r = GZW_REASON_BAD_ARGUMENT;

    gzw_set_reason(why, r);
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    memset(&leaf, 0, sizeof(leaf));
    if (!ctx || !account_xpub) return 0;
    if (!gzw_bip86_path(net, account, change, index, path)) return 0;
    /* An account key sits at depth 3 with the account as its hardened index. */
    if (account_xpub->depth != 3 || account_xpub->child_number != path[2]) return 0;
    if (gzw_bip32_derive_pub(ctx, account_xpub, path + 3, 2, &leaf, &r)) {
        r = output_from_pubkey33(ctx, net, path, leaf.pubkey, out) ? GZW_REASON_OK
                                                                   : GZW_REASON_INTERNAL;
    }
    gzw_wipe(&leaf, sizeof(leaf));
    gzw_set_reason(why, r);
    return r == GZW_REASON_OK;
}

int gzw_bip86_output_from_master(const secp256k1_context *ctx,
                                 const gzw_xprv *master, gzw_network net,
                                 uint32_t account, uint32_t change,
                                 uint32_t index, gzw_bip86_output *out,
                                 gzw_reason *why) {
    uint32_t path[5];
    gzw_xprv acct, leaf;
    gzw_xpub acct_pub, leaf_pub;
    gzw_bip86_output via_priv, via_pub;
    gzw_reason r = GZW_REASON_BAD_ARGUMENT;

    gzw_set_reason(why, r);
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    memset(&acct, 0, sizeof(acct));
    memset(&leaf, 0, sizeof(leaf));
    memset(&acct_pub, 0, sizeof(acct_pub));
    memset(&leaf_pub, 0, sizeof(leaf_pub));
    memset(&via_priv, 0, sizeof(via_priv));
    memset(&via_pub, 0, sizeof(via_pub));
    if (!ctx || !master) return 0;
    if (!gzw_bip86_path(net, account, change, index, path)) return 0;

    if (!gzw_bip86_account_xprv(ctx, master, net, account, &acct, &r)) goto done;

    /* Way 1: private derivation to the leaf, then its public key. */
    if (!gzw_bip32_derive_priv(ctx, &acct, path + 3, 2, &leaf, &r)) goto done;
    r = GZW_REASON_INTERNAL;
    if (!gzw_bip32_neuter(ctx, &leaf, &leaf_pub)) goto done;
    if (!output_from_pubkey33(ctx, net, path, leaf_pub.pubkey, &via_priv)) goto done;

    /* Way 2: public derivation below the account key. */
    if (!gzw_bip32_neuter(ctx, &acct, &acct_pub)) goto done;
    if (!gzw_bip86_output_from_xpub(ctx, &acct_pub, net, account, change, index,
                                    &via_pub, &r))
        goto done;

    r = GZW_REASON_INTERNAL;
    if (memcmp(via_priv.path, via_pub.path, sizeof(via_priv.path)) != 0 ||
        memcmp(via_priv.internal_key, via_pub.internal_key, 32) != 0 ||
        memcmp(via_priv.output_key, via_pub.output_key, 32) != 0 ||
        memcmp(via_priv.script_pubkey, via_pub.script_pubkey, 34) != 0 ||
        strcmp(via_priv.address, via_pub.address) != 0)
        goto done;
    *out = via_priv;
    r = GZW_REASON_OK;

done:
    gzw_wipe(&acct, sizeof(acct));
    gzw_wipe(&leaf, sizeof(leaf));
    /* Public values, wiped all the same: they tie this wallet's addresses
       together for anyone who can read old stack memory. */
    gzw_wipe(&acct_pub, sizeof(acct_pub));
    gzw_wipe(&leaf_pub, sizeof(leaf_pub));
    gzw_wipe(&via_priv, sizeof(via_priv));
    gzw_wipe(&via_pub, sizeof(via_pub));
    if (r != GZW_REASON_OK) memset(out, 0, sizeof(*out));
    gzw_set_reason(why, r);
    return r == GZW_REASON_OK;
}

int gzw_taproot_tweak_seckey(const secp256k1_context *ctx,
                             const unsigned char seckey32[32],
                             secp256k1_keypair *keypair_out,
                             unsigned char output_key_out32[32]) {
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey internal, tweaked;
    unsigned char sk[32], internal32[32], tweak[32], q_from_pair[32], q_from_pub[32];
    int ok = 0;

    if (!keypair_out) {
        if (output_key_out32) memset(output_key_out32, 0, 32);
        return 0;
    }
    memset(sk, 0, sizeof(sk));
    /* Copy first: output_key_out32 may be the same buffer as seckey32. */
    if (seckey32) memcpy(sk, seckey32, 32);
    if (output_key_out32) memset(output_key_out32, 0, 32);
    gzw_wipe(keypair_out, sizeof(*keypair_out));
    memset(&kp, 0, sizeof(kp));
    if (!ctx || !seckey32) goto done;

    if (!secp256k1_keypair_create(ctx, &kp, sk)) goto done;
    if (!secp256k1_keypair_xonly_pub(ctx, &internal, NULL, &kp)) goto done;
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal32, &internal)) goto done;
    if (!taptweak(ctx, internal32, tweak)) goto done;
    /* Negates the secret key first when its point has odd Y, then adds t. */
    if (!secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak)) goto done;

    /* The pair's public key must be the output key computed from the public
       side alone. */
    if (!secp256k1_keypair_xonly_pub(ctx, &tweaked, NULL, &kp)) goto done;
    if (!secp256k1_xonly_pubkey_serialize(ctx, q_from_pair, &tweaked)) goto done;
    if (!gzw_taproot_output_key(ctx, internal32, q_from_pub, NULL)) goto done;
    if (memcmp(q_from_pair, q_from_pub, 32) != 0) goto done;

    *keypair_out = kp;
    if (output_key_out32) memcpy(output_key_out32, q_from_pair, 32);
    ok = 1;

done:
    gzw_wipe(sk, sizeof(sk));
    gzw_wipe(&kp, sizeof(kp));
    if (!ok) gzw_wipe(keypair_out, sizeof(*keypair_out));
    return ok;
}

int gzw_bip86_tweaked_keypair(const secp256k1_context *ctx,
                              const gzw_xprv *master, gzw_network net,
                              uint32_t account, uint32_t change, uint32_t index,
                              secp256k1_keypair *keypair_out,
                              gzw_bip86_output *output_out, gzw_reason *why) {
    uint32_t path[5];
    gzw_xprv leaf;
    gzw_bip86_output output;
    unsigned char q[32];
    gzw_reason r = GZW_REASON_BAD_ARGUMENT;

    gzw_set_reason(why, r);
    if (output_out) memset(output_out, 0, sizeof(*output_out));
    if (!keypair_out) return 0;
    gzw_wipe(keypair_out, sizeof(*keypair_out));
    memset(&leaf, 0, sizeof(leaf));
    memset(&output, 0, sizeof(output));
    if (!ctx || !master || master->depth != 0) return 0;
    if (!gzw_bip86_path(net, account, change, index, path)) return 0;

    if (!gzw_bip86_output_from_master(ctx, master, net, account, change, index,
                                      &output, &r))
        goto done;
    if (!gzw_bip32_derive_priv(ctx, master, path, 5, &leaf, &r)) goto done;
    r = GZW_REASON_INTERNAL;
    if (!gzw_taproot_tweak_seckey(ctx, leaf.key, keypair_out, q)) goto done;
    /* The key that signs must be the key the address pays to. */
    if (memcmp(q, output.output_key, 32) != 0) goto done;

    if (output_out) *output_out = output;
    r = GZW_REASON_OK;

done:
    gzw_wipe(&leaf, sizeof(leaf));
    gzw_wipe(&output, sizeof(output));
    if (r != GZW_REASON_OK) {
        gzw_wipe(keypair_out, sizeof(*keypair_out));
        if (output_out) memset(output_out, 0, sizeof(*output_out));
    }
    gzw_set_reason(why, r);
    return r == GZW_REASON_OK;
}
