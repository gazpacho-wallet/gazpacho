#!/bin/sh
# Break-checks for the wallet key code: remove or damage one protection at a
# time in a scratch copy of the repository, rebuild, and require that a test
# fails.  A fault that no test notices is reported as SURVIVED and the script
# exits non-zero.
#
# usage: break-checks.sh REPO SCRATCH_DIR [SECP256K1_SOURCE_DIR]
#   REPO                  the repository to copy (it is not modified)
#   SCRATCH_DIR           where the copy and its build go (removed first)
#   SECP256K1_SOURCE_DIR  an already fetched secp256k1-zkp tree, to skip the download
set -u
repo="$1"; scratch="$2"; secp="${3:-}"
rm -rf "$scratch"; mkdir -p "$scratch/src"
(cd "$repo" && git ls-files -co --exclude-standard | tar cf - -T -) | (cd "$scratch/src" && tar xf -)
src="$scratch/src"; build="$scratch/build"
opts="-DCMAKE_BUILD_TYPE=Release"
[ -n "$secp" ] && opts="$opts -DFETCHCONTENT_SOURCE_DIR_SECP256K1-ZKP=$secp"
cmake -S "$src" -B "$build" $opts >"$scratch/configure.out" 2>&1 || { echo "configure failed"; exit 2; }
cmake --build "$build" -j4 >"$scratch/build0.out" 2>&1 || { echo "clean build failed"; exit 2; }
(cd "$build" && ctest >"$scratch/ctest0.out" 2>&1) || { echo "tests fail before any fault"; exit 2; }
echo "baseline: $(grep 'tests passed' "$scratch/ctest0.out")"

survived=0; n=0
mut() { # mut NAME FILE SED-EXPRESSION WHAT-WAS-BROKEN
  name="$1"; file="$src/$2"; expr="$3"; what="$4"; n=$((n + 1))
  cp "$file" "$scratch/keep"
  sed -i "$expr" "$file"
  if cmp -s "$file" "$scratch/keep"; then
    echo "$name: FAULT DID NOT APPLY"; survived=$((survived + 1)); return
  fi
  if ! cmake --build "$build" -j4 >"$scratch/build.out" 2>&1; then
    echo "$name: BUILD ERROR (not a valid break-check)"; survived=$((survived + 1))
  else
    (cd "$build" && ctest >"$scratch/ctest.out" 2>&1)
    failed=$(sed -n 's/^[[:space:]]*[0-9][0-9]* - \([a-z_0-9]*\) (.*$/\1/p' "$scratch/ctest.out" | tr '\n' ' ')
    if [ -n "$failed" ]; then
      echo "$name: caught by: $failed-- broke: $what"
    else
      echo "$name: SURVIVED -- broke: $what"; survived=$((survived + 1))
    fi
  fi
  cp "$scratch/keep" "$file"
}

A=wallet/src/address.c; B=wallet/src/bip32.c; P=wallet/src/phrase.c; T=wallet/src/taproot.c
M=tools/gz-wallet-keys/main.c

# --- address checksum -------------------------------------------------------
mut checksum-constant $A 's/#define BECH32M_CONST 0x2bc830a3u/#define BECH32M_CONST 0x2bc830a4u/' \
  "Bech32m checksum constant changed by one (addresses written and read with a wrong checksum)"
mut checksum-not-verified $A 's/if (pm != BECH32_CONST \&\& pm != BECH32M_CONST) return GZW_BECH32_NONE;//; s/return pm == BECH32M_CONST ? GZW_BECH32_BECH32M : GZW_BECH32_BECH32;/return pm == BECH32_CONST ? GZW_BECH32_BECH32 : GZW_BECH32_BECH32M;/' \
  "address checksum no longer verified when reading an address"
mut checksum-kind-rule $A 's/if (version != 0 \&\& kind != GZW_BECH32_BECH32M) return 0;//' \
  "taproot address accepted with the old Bech32 checksum"
mut mixed-case-accepted $A 's/if (have_lower \&\& have_upper) return GZW_BECH32_NONE;/if (0 \&\& have_lower \&\& have_upper) return GZW_BECH32_NONE;/' \
  "mixed-case addresses accepted"
mut padding-rule $A 's/if ((acc \& ((1u << bits) - 1u)) != 0) return 0;//' \
  "non-zero padding bits accepted in an address"
mut program-length-rule $A 's/if (plen < 2 || plen > 40) return 0;//' \
  "witness program length limits removed"
# --- network prefix ---------------------------------------------------------
mut prefix-test-networks $A 's/return "tb";/return "bc";/' \
  "signet/testnet addresses given the mainnet prefix bc"
mut prefix-regtest $A 's/return "bcrt";/return "tb";/' \
  "regtest addresses given the prefix tb"
mut prefix-not-compared $A 's/if (strcmp(got_hrp, hrp) != 0) return 0;//' \
  "an address of another network accepted (prefix not compared)"
# --- taproot tweak and script ----------------------------------------------
mut tweak-skipped $T 's/!gzw_taproot_output_key(ctx, out->internal_key, out->output_key, NULL) ||/((void)ctx, memcpy(out->output_key, out->internal_key, 32) == NULL) ||/' \
  "output key = internal key (no taproot tweak)"
mut tweak-tag $T "s/'T', 'w', 'e', 'a', 'k'}/'T', 'w', 'e', 'a', 'K'}/" \
  "tagged-hash tag changed from TapTweak to TapTweaK"
mut tweak-signing-key $T 's/if (!secp256k1_keypair_xonly_tweak_add(ctx, \&kp, tweak)) goto done;//' \
  "signing key pair returned without the tweak"
mut signing-key-check $T 's/if (!secp256k1_keypair_xonly_tweak_add(ctx, \&kp, tweak)) goto done;//; s/if (memcmp(q_from_pair, q_from_pub, 32) != 0) goto done;//; s/if (memcmp(q, output.output_key, 32) != 0) goto done;//' \
  "signing key pair untweaked and both internal consistency checks removed"
mut script-opcode $T 's/spk_out34\[0\] = 0x51;/spk_out34[0] = 0x50;/' \
  "scriptPubKey starts with 0x50 instead of OP_1"
mut witness-version $T 's/gzw_segwit_address_encode(hrp, 1, output_key32, 32, out)/gzw_segwit_address_encode(hrp, 2, output_key32, 32, out)/; s/if (version != 1 || plen != 32) return 0;//' \
  "address written with witness version 2 and the version check removed"
# --- derivation path --------------------------------------------------------
mut path-purpose $T 's/path_out\[0\] = 86u | GZW_HARDENED;/path_out[0] = 84u | GZW_HARDENED;/' \
  "purpose 84' instead of 86'"
mut path-coin-type $A '/case GZW_NET_REGTEST:/{n;s/\*coin_out = 1;/*coin_out = 0;/}' \
  "coin type 0 on the test networks"
mut path-coin-type-mainnet $A '/case GZW_NET_MAINNET:/{n;s/\*coin_out = 0;/*coin_out = 1;/}' \
  "coin type 1 on mainnet"
mut path-account-not-hardened $T 's/path_out\[2\] = account | GZW_HARDENED;/path_out[2] = account;/' \
  "account step not hardened"
mut path-change-index-swapped $T 's/path_out\[3\] = change;/path_out[3] = index;/; s/path_out\[4\] = index;/path_out[4] = change;/' \
  "change and index swapped in the path"
mut path-change-ignored $T 's/path_out\[3\] = change;/path_out[3] = 0;/' \
  "change outputs derived on the receiving chain"
# --- BIP 32 -----------------------------------------------------------------
mut hardened-ignored $B 's/    if (index \& GZW_HARDENED) {/    if (0) {/' \
  "hardened steps derived as non-hardened"
mut always-hardened $B 's/    if (index \& GZW_HARDENED) {/    if (1) {/' \
  "non-hardened steps derived as hardened"
mut hardened-from-public $B 's/if (index \& GZW_HARDENED) goto done;//' \
  "public derivation no longer refuses hardened indexes"
mut fingerprint $B 's/memcpy(out4, rmd, 4);/memcpy(out4, sha, 4);/' \
  "parent fingerprint taken from SHA-256 instead of RIPEMD160(SHA-256)"
mut xkey-checksum $B 's/if (!gzw_ct_equal(sum, raw + XKEY_RAW, 4)) return 0;//' \
  "extended-key text checksum not verified"
mut xkey-depth-zero-rule $B 's/if (raw\[4\] == 0 \&\& (raw\[5\]/if (0 \&\& (raw[5]/' \
  "master key text accepted with a parent fingerprint or index"
mut xkey-unknown-version $B 's/        return 0; \/\* unknown version \*\//        *is_private_out = 0; *mainnet_out = 1;/' \
  "unknown extended-key version bytes accepted"
mut xprv-range $B 's/if (!secp256k1_ec_seckey_verify(ctx, raw + 46)) goto done;//' \
  "private key 0 or >= n accepted in key text"
mut xprv-prefix $B 's/if (raw\[45\] != 0x00) goto done;//' \
  "private key text accepted without the 00 prefix byte"
mut xpub-prefix $B 's/if (raw\[45\] != 0x02 \&\& raw\[45\] != 0x03) goto done;//; s/if (!secp256k1_ec_pubkey_parse(ctx, \&pub, raw + 45, 33)) goto done;/(void)pub;/' \
  "public key text accepted without checking the point"
mut xkey-kind $B 's/    if (is_private) goto done;//' \
  "private key text accepted as a public key"
# --- recovery phrase --------------------------------------------------------
mut phrase-check $P 's/switch (bip39_check(phrase)) {/switch (BIP39_OK) {/' \
  "recovery phrase checksum and word checks skipped"
mut phrase-checksum-byte $P 's/buf\[32\] = hash\[0\];/buf[32] = 0;/' \
  "new phrases written with a zero checksum"
mut phrase-word-order $P 's/size_t bit = w \* 11 + b;/size_t bit = (23 - w) * 11 + b;/' \
  "new phrases written with the words in reverse order"
mut phrase-passphrase-ascii $P 's/if (\*p >= 0x80) return 0;/if (0 \&\& *p >= 0x80) return 0;/' \
  "non-ASCII passphrase accepted without normalisation"
# --- hygiene ----------------------------------------------------------------
mut wipe-removed $B 's/if (p \&\& len) OPENSSL_cleanse(p, len);/(void)p; (void)len;/' \
  "gzw_wipe does nothing"
mut ct-equal $B 's/return CRYPTO_memcmp(a, b, len) == 0;/return 1;/' \
  "gzw_ct_equal always says equal"
# --- the tool ---------------------------------------------------------------
mut tool-mainnet $M 's/if (\*net == GZW_NET_MAINNET) {/if (0) {/' \
  "tool no longer refuses mainnet"
mut tool-overwrite $M 's/O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600/O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600/' \
  "tool overwrites an existing phrase file"
mut tool-file-mode $M 's/O_CLOEXEC, 0600);/O_CLOEXEC, 0644);/; s/fchmod(fd, 0600)/fchmod(fd, 0644)/' \
  "phrase file created readable by everyone"
mut tool-reads-open-file $M 's/if ((st.st_mode \& 077) != 0) {/if (0) {/' \
  "tool reads a phrase file that other users can read"
mut tool-prints-phrase $M 's/printf("address: %s\\n", check.address);/printf("address: %s\\n%s\\n", check.address, phrase);/' \
  "tool prints the recovery phrase"

echo "break-checks: $n faults, $survived not caught"
test "$survived" = 0
