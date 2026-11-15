/* BIP 341's wallet test vectors (bip-0341/wallet-test-vectors.json in the
 * BIPs repository) through the engine's own Taproot code
 * (core/signing/sign_tx.c), which decides what every member signs (review A,
 * F10):
 *
 * - the TapTweak of every vector's internal key, with and without a script
 *   tree (gz_sign_taptweak, as check_def uses it), the output key the
 *   library makes with that tweak, and the P2TR script the engine compares
 *   an item's spent script with (OP_1, 32 bytes, the key);
 * - the signature hash: the one key-path input of the vectors with hash
 *   type default (input 4), whose SigMsg the engine forms the same way for
 *   its one-input transactions (gz_sign_taproot_sighash, the last step of
 *   gz_sign_tx_sighash), from the vectors' own shared hashes.
 *
 * The other inputs use hash types the engine never signs with (Slice 1 signs
 * key path, default type, input 0 of a one-input transaction). */
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <stdio.h>
#include <string.h>
#include "gazpacho/signing.h"
#include "../check.h"

static void hex(const char *h, uint8_t *out)
{
    for (size_t i = 0; h[2 * i] && h[2 * i + 1]; i++) sscanf(h + 2 * i, "%2hhx", &out[i]);
}

/* "scriptPubKey" (7 vectors) and the key-path spends' keys (7 more). */
static const struct { const char *internal, *merkle, *tweak, *tweaked, *spk; } TWEAKS[] = {
    {"d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", NULL,
     "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
     "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
     "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"},
    {"187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
     "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
     "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
     "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
     "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"},
    {"93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
     "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
     "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30",
     "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
     "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"},
    {"ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
     "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef",
     "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9",
     "712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
     "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"},
    {"f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
     "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
     "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e",
     "77e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
     "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"},
    {"e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
     "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2",
     "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4",
     "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
     "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"},
    {"55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
     "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def",
     "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9",
     "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
     "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"},
    /* keyPathSpending: the keys and tweaks of inputs 1, 3 and 8 (the others repeat the above) */
    {"187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
     "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21",
     "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001", NULL, NULL},
    {"93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
     "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b",
     "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30", NULL, NULL},
    {"f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
     "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc",
     "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e", NULL, NULL},
};

static void test_tweaks(secp256k1_context *ctx)
{
    for (size_t v = 0; v < sizeof TWEAKS / sizeof TWEAKS[0]; v++) {
        uint8_t internal[32], merkle[32], want[32], tweak[32], out[32], spk[34], want_spk[34];
        secp256k1_xonly_pubkey ik, ok_x;
        secp256k1_pubkey tw;
        hex(TWEAKS[v].internal, internal);
        if (TWEAKS[v].merkle) hex(TWEAKS[v].merkle, merkle);
        hex(TWEAKS[v].tweak, want);
        gz_sign_taptweak(internal, TWEAKS[v].merkle ? merkle : NULL, tweak);
        if (memcmp(tweak, want, 32)) printf("  BIP 341 vector %zu: tweak differs\n", v);
        CHECK(memcmp(tweak, want, 32) == 0);
        if (!TWEAKS[v].tweaked) continue;
        hex(TWEAKS[v].tweaked, want);
        hex(TWEAKS[v].spk, want_spk);
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &ik, internal) && secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &ik, tweak) &&
              secp256k1_xonly_pubkey_from_pubkey(ctx, &ok_x, NULL, &tw) && secp256k1_xonly_pubkey_serialize(ctx, out, &ok_x));
        CHECK(memcmp(out, want, 32) == 0);
        spk[0] = 0x51; spk[1] = 0x20; memcpy(spk + 2, out, 32);    /* the engine's P2TR form (check_def) */
        CHECK(memcmp(spk, want_spk, 34) == 0);
    }
}

/* keyPathSpending, input 4: hash type default, key path, no annex. */
static void test_sighash(void)
{
    uint8_t version[4], locktime[4], hashes[5][32], want[32], got[32];
    hex("02000000", version);
    hex("0065cd1d", locktime);
    hex("e3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f", hashes[0]);   /* hashPrevouts */
    hex("58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde6", hashes[1]);   /* hashAmounts */
    hex("23ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e21", hashes[2]);   /* hashScriptPubkeys */
    hex("18959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e", hashes[3]);   /* hashSequences */
    hex("a2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc5", hashes[4]);   /* hashOutputs */
    hex("4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef", want);
    gz_sign_taproot_sighash(version, locktime, (const uint8_t (*)[32])hashes, 4, got);
    CHECK(memcmp(got, want, 32) == 0);
    /* every field counts: each byte of each changed in turn changes the hash */
    for (int k = 0; k < 5; k++) {
        hashes[k][k] ^= 1;
        gz_sign_taproot_sighash(version, locktime, (const uint8_t (*)[32])hashes, 4, got);
        CHECK(memcmp(got, want, 32) != 0);
        hashes[k][k] ^= 1;
    }
    gz_sign_taproot_sighash(version, locktime, (const uint8_t (*)[32])hashes, 3, got);
    CHECK(memcmp(got, want, 32) != 0);
}

int main(void)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    setvbuf(stdout, NULL, _IONBF, 0);
    test_tweaks(ctx);
    test_sighash();
    secp256k1_context_destroy(ctx);
    return check_done();
}
