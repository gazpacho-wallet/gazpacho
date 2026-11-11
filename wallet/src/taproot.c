/* Single-key taproot outputs: BIP 341 tweak with no script tree, BIP 86 paths. */
#include "gazpacho/wallet_keys.h"

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
    unsigned char tweak[32];
    int parity = 0;

    if (!output_key_out32) return 0;
    memset(output_key_out32, 0, 32);
    if (!ctx || !internal_key32) return 0;

    /* lift_x(P): fails if the 32 bytes are not the X of a curve point. */
    if (!secp256k1_xonly_pubkey_parse(ctx, &internal, internal_key32)) return 0;
    if (!taptweak(ctx, internal_key32, tweak)) return 0;
    /* Q = P + t*G; fails if t is not below the order or Q is infinity. */
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &output, &internal, tweak)) return 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &output_xonly, &parity, &output))
        return 0;
    if (!secp256k1_xonly_pubkey_serialize(ctx, output_key_out32, &output_xonly))
        return 0;
    /* Independent check of the relation between Q, P and t. */
    if (!secp256k1_xonly_pubkey_tweak_add_check(ctx, output_key_out32, parity,
                                                &internal, tweak)) {
        memset(output_key_out32, 0, 32);
        return 0;
    }
    if (parity_out) *parity_out = parity;
    return 1;
}

void gzw_p2tr_script_pubkey(const unsigned char output_key32[32],
                            unsigned char spk_out34[34]) {
    spk_out34[0] = 0x51; /* OP_1 */
    spk_out34[1] = 0x20; /* push 32 bytes */
    memcpy(spk_out34 + 2, output_key32, 32);
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
                           gzw_network net, uint32_t account, gzw_xprv *out) {
    uint32_t path[5];

    if (!out) return 0;
    gzw_wipe(out, sizeof(*out));
    if (!ctx || !master) return 0;
    /* The account key hangs off the wallet's master key, not off any key. */
    if (master->depth != 0) return 0;
    if (!gzw_bip86_path(net, account, 0, 0, path)) return 0;
    return gzw_bip32_derive_priv(ctx, master, path, 3, out);
}

int gzw_bip86_account_xpub(const secp256k1_context *ctx, const gzw_xprv *master,
                           gzw_network net, uint32_t account, gzw_xpub *out) {
    gzw_xprv acct;
    int ok;

    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    ok = gzw_bip86_account_xprv(ctx, master, net, account, &acct) &&
         gzw_bip32_neuter(ctx, &acct, out);
    gzw_wipe(&acct, sizeof(acct));
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
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
        !gzw_p2tr_address(net, out->output_key, out->address)) {
        memset(out, 0, sizeof(*out));
        return 0;
    }
    gzw_p2tr_script_pubkey(out->output_key, out->script_pubkey);
    return 1;
}

int gzw_bip86_output_from_xpub(const secp256k1_context *ctx,
                               const gzw_xpub *account_xpub, gzw_network net,
                               uint32_t account, uint32_t change, uint32_t index,
                               gzw_bip86_output *out) {
    uint32_t path[5];
    gzw_xpub leaf;

    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!ctx || !account_xpub) return 0;
    if (!gzw_bip86_path(net, account, change, index, path)) return 0;
    /* An account key sits at depth 3 with the account as its hardened index. */
    if (account_xpub->depth != 3 || account_xpub->child_number != path[2]) return 0;
    if (!gzw_bip32_derive_pub(ctx, account_xpub, path + 3, 2, &leaf)) return 0;
    return output_from_pubkey33(ctx, net, path, leaf.pubkey, out);
}

int gzw_bip86_output_from_master(const secp256k1_context *ctx,
                                 const gzw_xprv *master, gzw_network net,
                                 uint32_t account, uint32_t change,
                                 uint32_t index, gzw_bip86_output *out) {
    uint32_t path[5];
    gzw_xprv acct, leaf;
    gzw_xpub acct_pub, leaf_pub;
    gzw_bip86_output via_priv, via_pub;
    int ok = 0;

    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    memset(&acct, 0, sizeof(acct));
    memset(&leaf, 0, sizeof(leaf));
    if (!ctx || !master) return 0;
    if (!gzw_bip86_path(net, account, change, index, path)) return 0;

    if (!gzw_bip86_account_xprv(ctx, master, net, account, &acct)) goto done;

    /* Way 1: private derivation to the leaf, then its public key. */
    if (!gzw_bip32_derive_priv(ctx, &acct, path + 3, 2, &leaf)) goto done;
    if (!gzw_bip32_neuter(ctx, &leaf, &leaf_pub)) goto done;
    if (!output_from_pubkey33(ctx, net, path, leaf_pub.pubkey, &via_priv)) goto done;

    /* Way 2: public derivation below the account key. */
    if (!gzw_bip32_neuter(ctx, &acct, &acct_pub)) goto done;
    if (!gzw_bip86_output_from_xpub(ctx, &acct_pub, net, account, change, index,
                                    &via_pub))
        goto done;

    if (memcmp(via_priv.path, via_pub.path, sizeof(via_priv.path)) != 0 ||
        memcmp(via_priv.internal_key, via_pub.internal_key, 32) != 0 ||
        memcmp(via_priv.output_key, via_pub.output_key, 32) != 0 ||
        memcmp(via_priv.script_pubkey, via_pub.script_pubkey, 34) != 0 ||
        strcmp(via_priv.address, via_pub.address) != 0)
        goto done;
    *out = via_priv;
    ok = 1;

done:
    gzw_wipe(&acct, sizeof(acct));
    gzw_wipe(&leaf, sizeof(leaf));
    if (!ok) memset(out, 0, sizeof(*out));
    return ok;
}

int gzw_taproot_tweak_seckey(const secp256k1_context *ctx,
                             const unsigned char seckey32[32],
                             secp256k1_keypair *keypair_out,
                             unsigned char output_key_out32[32]) {
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey internal, tweaked;
    unsigned char internal32[32], tweak[32], q_from_pair[32], q_from_pub[32];
    int ok = 0;

    if (output_key_out32) memset(output_key_out32, 0, 32);
    if (!keypair_out) return 0;
    gzw_wipe(keypair_out, sizeof(*keypair_out));
    if (!ctx || !seckey32) return 0;

    if (!secp256k1_keypair_create(ctx, &kp, seckey32)) goto done;
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
    gzw_wipe(&kp, sizeof(kp));
    if (!ok) gzw_wipe(keypair_out, sizeof(*keypair_out));
    return ok;
}

int gzw_bip86_tweaked_keypair(const secp256k1_context *ctx,
                              const gzw_xprv *master, gzw_network net,
                              uint32_t account, uint32_t change, uint32_t index,
                              secp256k1_keypair *keypair_out,
                              gzw_bip86_output *output_out) {
    uint32_t path[5];
    gzw_xprv leaf;
    gzw_bip86_output output;
    unsigned char q[32];
    int ok = 0;

    if (output_out) memset(output_out, 0, sizeof(*output_out));
    if (!keypair_out) return 0;
    gzw_wipe(keypair_out, sizeof(*keypair_out));
    memset(&leaf, 0, sizeof(leaf));
    if (!ctx || !master || master->depth != 0) return 0;
    if (!gzw_bip86_path(net, account, change, index, path)) return 0;

    if (!gzw_bip86_output_from_master(ctx, master, net, account, change, index,
                                      &output))
        goto done;
    if (!gzw_bip32_derive_priv(ctx, master, path, 5, &leaf)) goto done;
    if (!gzw_taproot_tweak_seckey(ctx, leaf.key, keypair_out, q)) goto done;
    /* The key that signs must be the key the address pays to. */
    if (memcmp(q, output.output_key, 32) != 0) goto done;

    if (output_out) *output_out = output;
    ok = 1;

done:
    gzw_wipe(&leaf, sizeof(leaf));
    if (!ok) {
        gzw_wipe(keypair_out, sizeof(*keypair_out));
        if (output_out) memset(output_out, 0, sizeof(*output_out));
    }
    return ok;
}
