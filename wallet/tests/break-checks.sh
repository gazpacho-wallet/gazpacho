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
#
# It is registered with CTest as wallet_break_checks (label "slow") in builds
# without sanitizers, so CI runs it; configure with -DGZW_BREAK_CHECKS=OFF or
# run "ctest -LE slow" to leave it out.
set -u
repo="$1"; scratch="$2"; secp="${3:-}"
rm -rf "$scratch"; mkdir -p "$scratch/src"
if (cd "$repo" && git rev-parse --is-inside-work-tree >/dev/null 2>&1); then
  (cd "$repo" && git ls-files -co --exclude-standard | tar cf - -T -) | (cd "$scratch/src" && tar xf -)
else
  (cd "$repo" && tar cf - --exclude='./build*' --exclude='./.git' .) | (cd "$scratch/src" && tar xf -)
fi
src="$scratch/src"; build="$scratch/build"
# GZW_BREAK_CHECKS=OFF: the copy must not run this script again from its own tests.
# GZ_CHAIN_TESTS=OFF: the chain port's tests (ports/chain) cannot notice a wallet
# fault, and running them for every fault would only add time.
# GZ_VALGRIND_TESTS=OFF: the same for the core's tests run again under valgrind
# (about a minute per fault, which passed the CI job's time limit).
opts="-DCMAKE_BUILD_TYPE=Release -DGZW_BREAK_CHECKS=OFF -DGZ_CHAIN_TESTS=OFF -DGZ_VALGRIND_TESTS=OFF"
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
    # wallet_tx_tool_chain is left out of the runs with a fault: it waits on
    # the chain port's retry pauses (about 30 s), which over every fault would
    # pass the CI job's time limit; it ran in the baseline above, and the
    # offline tool tests still run with every fault.
    (cd "$build" && ctest -j4 -E '^wallet_tx_tool_chain$' >"$scratch/ctest.out" 2>&1)
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
mut checksum-generator $A 's/0x26508e6du/0x26508e6eu/' "one checksum generator constant changed"
mut checksum-not-verified $A 's/if (pm != BECH32_CONST \&\& pm != BECH32M_CONST) return GZW_BECH32_NONE;//; s/return pm == BECH32M_CONST ? GZW_BECH32_BECH32M : GZW_BECH32_BECH32;/return pm == BECH32_CONST ? GZW_BECH32_BECH32 : GZW_BECH32_BECH32M;/' \
  "address checksum no longer verified when reading an address"
mut checksum-kind-rule $A 's/if (version != 0 \&\& kind != GZW_BECH32_BECH32M) return 0;//' \
  "taproot address accepted with the old Bech32 checksum"
mut checksum-kind-rule-v0 $A 's/if (version == 0 \&\& kind != GZW_BECH32_BECH32) return 0;//' \
  "version-0 address accepted with the Bech32m checksum"
mut mixed-case-accepted $A 's/if (have_lower \&\& have_upper) return GZW_BECH32_NONE;/if (0 \&\& have_lower \&\& have_upper) return GZW_BECH32_NONE;/' \
  "mixed-case addresses accepted"
mut padding-rule $A 's/if ((acc \& ((1u << bits) - 1u)) != 0) return 0;//' \
  "non-zero padding bits accepted in an address"
mut padding-length $A 's/    if (bits >= 5) return 0;//' "more than 4 bits of padding accepted"
mut program-length-rule $A 's/if (plen < 2 || plen > 40) return 0;//' \
  "witness program length limits removed"
mut v0-length-decode $A 's/if (version == 0 \&\& plen != 20 \&\& plen != 32) return 0;//' \
  "version-0 address accepted with a program that is not 20 or 32 bytes"
mut v0-length-encode $A 's/if (witness_version == 0 \&\& program_len != 20 \&\& program_len != 32) return 0;//' \
  "version-0 address written with a program that is not 20 or 32 bytes"
mut version-max-decode $A 's/if (version > 16) return 0;//' "witness version above 16 accepted"
mut version-max-encode $A 's/witness_version > 16/witness_version > 17/' "witness version 17 written"
mut program-min-encode $A 's/if (program_len < 2 || program_len > 40) return 0;/if (program_len > 40) return 0;/' \
  "encoder accepts programs shorter than 2 bytes"
mut max-length $A 's/if (len < 8 || len > BECH32_MAX_LEN) return GZW_BECH32_NONE;/if (len < 8) return GZW_BECH32_NONE;/' \
  "strings longer than 90 characters accepted (short prefix)"
mut charset-range $A 's/if (ch < 33 || ch > 126) return GZW_BECH32_NONE;/if (ch < 32 || ch > 127) return GZW_BECH32_NONE;/' \
  "characters 0x20 and 0x7F accepted in the prefix"
mut empty-hrp $A 's/if (sep == len || sep == 0 || sep > 83)/if (sep == len || sep > 83)/' "empty prefix accepted"
mut hrp-upper-encode $A 's/if (ch < 33 || ch > 126 || (ch >= .A. \&\& ch <= .Z.)) return 0;/if (ch < 33 || ch > 126) return 0;/' \
  "encoder accepts an upper-case prefix"
# --- network prefix and names -----------------------------------------------
mut prefix-test-networks $A 's/return "tb";/return "bc";/' \
  "signet/testnet addresses given the mainnet prefix bc"
mut prefix-regtest $A 's/return "bcrt";/return "tb";/' \
  "regtest addresses given the prefix tb"
mut prefix-not-compared $A 's/if (strcmp(got_hrp, hrp) != 0) return 0;//' \
  "an address of another network accepted (prefix not compared)"
mut net-name-testnet4 $A 's/return "testnet4";/return "testnet-4";/' "testnet4 spelled differently"
# --- taproot tweak and script ----------------------------------------------
mut tweak-skipped $T 's/!gzw_taproot_output_key(ctx, out->internal_key, out->output_key, NULL) ||/((void)ctx, memcpy(out->output_key, out->internal_key, 32) == NULL) ||/' \
  "output key = internal key (no taproot tweak)"
mut tweak-tag $T "s/'T', 'w', 'e', 'a', 'k'}/'T', 'w', 'e', 'a', 'K'}/" \
  "tagged-hash tag changed from TapTweak to TapTweaK"
mut tweak-signing-key $T 's/if (!secp256k1_keypair_xonly_tweak_add(ctx, \&kp, tweak)) goto done;//' \
  "signing key pair returned without the tweak"
mut signing-key-check $T 's/if (!secp256k1_keypair_xonly_tweak_add(ctx, \&kp, tweak)) goto done;//; s/if (memcmp(q_from_pair, q_from_pub, 32) != 0) goto done;//; s/if (memcmp(q, output.output_key, 32) != 0) goto done;//' \
  "signing key pair untweaked and both internal consistency checks removed"
mut parity-out $T 's/if (parity_out) \*parity_out = parity;/if (parity_out) *parity_out = 0;/' \
  "output key parity always reported as even"
mut script-opcode $T 's/spk_out34\[0\] = 0x51;/spk_out34[0] = 0x50;/' \
  "scriptPubKey starts with 0x50 instead of OP_1"
mut script-push-len $T 's/spk_out34\[1\] = 0x20;/spk_out34[1] = 0x21;/' "scriptPubKey push length 0x21"
mut script-null-check $T 's/    if (!output_key32) {/    if (0) {/' \
  "gzw_p2tr_script_pubkey no longer checks for a NULL key"
mut witness-version $T 's/gzw_segwit_address_encode(hrp, 1, output_key32, 32, out)/gzw_segwit_address_encode(hrp, 2, output_key32, 32, out)/; s/if (version != 1 || plen != 32) return 0;//' \
  "address written with witness version 2 and the version check removed"
mut p2tr-decode-version $T 's/if (version != 1 || plen != 32) return 0;/if (plen != 32) return 0;/' \
  "a 32-byte address of another witness version decoded as a taproot key"
mut p2tr-decode-length $T 's/if (version != 1 || plen != 32) return 0;/if (version != 1) return 0;/' \
  "a version-1 address with a program that is not 32 bytes decoded as a taproot key"
mut alias-output-key $T 's/if (!secp256k1_xonly_pubkey_parse(ctx, \&internal, p32)) goto done;/if (!secp256k1_xonly_pubkey_parse(ctx, \&internal, internal_key32)) goto done;/' \
  "gzw_taproot_output_key reads its input after clearing the output (breaks out == in)"
mut alias-account-key $T 's/    if (!ctx || !master || master->depth != 0 ||/    gzw_wipe(out, sizeof(*out)); if (!ctx || !master || master->depth != 0 ||/' \
  "gzw_bip86_account_xprv clears the output before reading the master key (breaks out == master)"
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
mut account-limit $T 's/account >= GZW_HARDENED || index/account > GZW_HARDENED || index/' "account 2^31 accepted"
mut index-limit $T 's/index >= GZW_HARDENED || change/index > GZW_HARDENED || change/' "index 2^31 accepted"
mut change-limit $T 's/change > 1) return 0;/change > 2) return 0;/' "change value 2 accepted"
mut master-depth-rule $T 's/    if (!ctx || !master || master->depth != 0 ||/    if (!ctx || !master ||/; s/if (!ctx || !master || master->depth != 0) return 0;/if (!ctx || !master) return 0;/' \
  "BIP 86 keys derived from a key that is not a master key"
mut xpub-depth-rule $T 's/if (account_xpub->depth != 3 || account_xpub->child_number != path\[2\]) return 0;/if (account_xpub->child_number != path[2]) return 0;/' \
  "account xpub of the wrong depth accepted"
mut xpub-account-rule $T 's/if (account_xpub->depth != 3 || account_xpub->child_number != path\[2\]) return 0;/if (account_xpub->depth != 3) return 0;/' \
  "account xpub of another account accepted"
# --- BIP 32 -----------------------------------------------------------------
mut hardened-ignored $B 's/    if (index \& GZW_HARDENED) {/    if (0) {/' \
  "hardened steps derived as non-hardened"
mut always-hardened $B 's/    if (index \& GZW_HARDENED) {/    if (1) {/' \
  "non-hardened steps derived as hardened"
mut hardened-boundary $B 's/    if (index \& GZW_HARDENED) {/    if (index > GZW_HARDENED) {/' \
  "index exactly 2^31 derived as non-hardened"
mut hardened-from-public $B 's/if (index \& GZW_HARDENED) goto done;//' \
  "public derivation no longer refuses hardened indexes"
mut index-byte-order $B 's/out\[0\] = (unsigned char)(v >> 24);/out[0] = (unsigned char)v;/; s/out\[3\] = (unsigned char)v;/out[3] = (unsigned char)(v >> 24);/' \
  "index serialised with bytes 0 and 3 swapped"
mut depth-limit $B 's/if (parent->depth == 255) goto done;//' "derivation past depth 255 (depth wraps to 0)"
mut seed-min $B 's/seed_len < 16/seed_len < 15/' "15-byte seed accepted"
mut seed-max $B 's/seed_len > 64/seed_len > 65/' "65-byte seed accepted"
mut master-range-check $B 's/    if (!secp256k1_ec_seckey_verify(ctx, I)) goto done;//' \
  "master key not checked for 0 or >= n"
mut parent-key-check $B 's/    if (!secp256k1_ec_seckey_verify(ctx, parent->key)) goto done;//' \
  "an invalid parent key is no longer told apart from an invalid child"
mut invalid-child-reason $B '/which this index has no key/,/seckey_tweak_add/s/r = GZW_REASON_INVALID_CHILD;/r = GZW_REASON_INTERNAL;/' \
  "BIP 32 invalid child reported as an internal error instead of 'use the next index'"
mut invalid-child-reason-pub $B '/use the next index\. \*\//,/pubkey_tweak_add/s/r = GZW_REASON_INVALID_CHILD;/r = GZW_REASON_BAD_ARGUMENT;/' \
  "invalid public child reported as a bad argument"
mut fingerprint $B 's/memcpy(out4, rmd, 4);/memcpy(out4, sha, 4);/' \
  "parent fingerprint taken from SHA-256 instead of RIPEMD160(SHA-256)"
mut fingerprint-offset $B 's/memcpy(out4, rmd, 4);/memcpy(out4, rmd + 16, 4);/' "fingerprint from the last 4 hash bytes"
mut xkey-checksum $B 's/if (!gzw_ct_equal(sum, raw + XKEY_RAW, 4)) return 0;//' \
  "extended-key text checksum not verified"
mut xkey-depth-zero-rule $B 's/if (raw\[4\] == 0 \&\& (raw\[5\]/if (0 \&\& (raw[5]/' \
  "master key text accepted with a parent fingerprint or index"
mut xkey-depth-zero-encode $B 's/    if (depth == 0 \&\&/    if (0 \&\&/' "master key written with a parent or an index"
mut xkey-unknown-version $B 's/        return 0; \/\* unknown version \*\//        *is_private_out = 0; *mainnet_out = 1;/' \
  "unknown extended-key version bytes accepted"
mut xkey-network-inverted $B 's/    return net == GZW_NET_MAINNET;/    return net != GZW_NET_MAINNET;/' \
  "key text written with the other network's version bytes"
mut xkey-network-unchecked $B 's/    if (!gzw_network_coin_type(net, \&coin)) return -1;/    (void)gzw_network_coin_type(net, \&coin);/' \
  "key text written for a value that is not a network"
mut xprv-range $B 's/if (!secp256k1_ec_seckey_verify(ctx, raw + 46)) goto done;//' \
  "private key 0 or >= n accepted in key text"
mut xprv-prefix $B 's/if (raw\[45\] != 0x00) goto done;//' \
  "private key text accepted without the 00 prefix byte"
mut xpub-prefix $B 's/if (raw\[45\] != 0x02 \&\& raw\[45\] != 0x03) goto done;//; s/if (!secp256k1_ec_pubkey_parse(ctx, \&pub, raw + 45, 33)) goto done;/(void)pub;/' \
  "public key text accepted without checking the point"
mut xpub-encode-prefix $B 's/        (xpub->pubkey\[0\] != 0x02 \&\& xpub->pubkey\[0\] != 0x03)) {/        0) {/' \
  "xpub text written for a key whose prefix byte is not 02 or 03"
mut xkey-kind $B 's/    if (is_private) goto done;//' \
  "private key text accepted as a public key"
mut b58-leading-ones $B 's/    while (zeros < slen \&\& str\[zeros\] == .1.) zeros++;//' \
  "extra leading 1 characters (non-canonical Base58) accepted in key text"
# --- recovery phrase --------------------------------------------------------
mut phrase-check $P 's/switch (bip39_check(phrase)) {/switch (BIP39_OK) {/' \
  "recovery phrase checksum and word checks skipped"
mut phrase-checksum-byte $P 's/buf\[32\] = hash\[0\];/buf[32] = 0;/' \
  "new phrases written with a zero checksum"
mut phrase-word-order $P 's/size_t bit = w \* 11 + b;/size_t bit = (23 - w) * 11 + b;/' \
  "new phrases written with the words in reverse order"
mut phrase-bit-order $P 's/(7 - bit % 8)/(bit % 8)/' "bits taken least significant first when making a phrase"
mut phrase-passphrase-ascii $P 's/if (\*p >= 0x80) return 0;/if (0 \&\& *p >= 0x80) return 0;/' \
  "non-ASCII passphrase accepted without normalisation"
mut phrase-passphrase-boundary $P 's/if (\*p >= 0x80) return 0;/if (*p > 0x80) return 0;/' \
  "passphrase byte 0x80 accepted"
# --- hygiene and the no-I/O rule --------------------------------------------
mut wipe-removed $B 's/if (p \&\& len) OPENSSL_cleanse(p, len);/(void)p; (void)len;/' \
  "gzw_wipe does nothing"
mut ct-equal $B 's/return CRYPTO_memcmp(a, b, len) == 0;/return 1;/' \
  "gzw_ct_equal always says equal"
mut lib-reads-clock $B 's/#include <string.h>/#include <string.h>\n#include <time.h>/; s/    memcpy(out->chain_code, I + 32, 32);/    memcpy(out->chain_code, I + 32, 32); { struct timespec ts; timespec_get(\&ts, TIME_UTC); out->depth = (uint8_t)(ts.tv_sec \& 0); }/' \
  "library reads the clock"
mut lib-opens-file $P 's/#include <string.h>/#include <string.h>\n#include <fcntl.h>\n#include <unistd.h>/; s/    phrase_out\[pos\] = .\\0.;/    phrase_out[pos] = 0; { int fd = openat(AT_FDCWD, "gz-break-check-leak", O_WRONLY | O_CREAT | O_APPEND, 0600); if (fd >= 0) { if (pwrite(fd, "x", 1, 0) < 0) {} close(fd); } }/' \
  "library creates and writes a file"
mut lib-logs-phrase $P 's/#include <string.h>/#include <string.h>\n#include <stdio.h>/; s/    phrase_out\[pos\] = .\\0.;/    phrase_out[pos] = 0; fprintf(stderr, "phrase: %s\\n", phrase_out);/' \
  "library writes every new recovery phrase to stderr"
mut lib-logs-key $B 's/#include <string.h>/#include <string.h>\n#include <stdio.h>/; s/    memcpy(out->key, I, 32);/    memcpy(out->key, I, 32); fprintf(stderr, "master key byte %d\\n", (int)I[0]);/' \
  "library writes master key material to stderr"
mut lib-reads-random $B 's/#include <string.h>/#include <string.h>\n#include <sys\/random.h>/; s/    memcpy(out->chain_code, I + 32, 32);/    memcpy(out->chain_code, I + 32, 32); { unsigned char x; if (getrandom(\&x, 1, 0) < 0) {} }/' \
  "library reads the system random source"
mut lib-global-state $A 's/static uint32_t polymod_step(uint32_t c, unsigned v) {/static unsigned long gzw_calls; static uint32_t polymod_step(uint32_t c, unsigned v) { gzw_calls++;/' \
  "library keeps a global counter"
mut lib-uses-heap $B 's/#include <string.h>/#include <string.h>\n#include <stdlib.h>/; s/    memcpy(out->chain_code, I + 32, 32);/    memcpy(out->chain_code, I + 32, 32); { void *volatile leak = malloc(64); if (leak) memcpy(leak, I, 64); }/' \
  "library copies key material to the heap"
# --- the tool ---------------------------------------------------------------
mut tool-mainnet $M 's/if (\*net == GZW_NET_MAINNET) {/if (0) {/' \
  "tool no longer refuses mainnet"
mut tool-overwrite $M 's/    if (lstat(out_path, \&st) == 0) {/    if (0 \&\& lstat(out_path, \&st) == 0) {/; s/    if (link(tmp_path, out_path) != 0) {/    if (rename(tmp_path, out_path) != 0) {/' \
  "tool overwrites an existing phrase file (rename instead of link)"
mut tool-link-guard $M 's/    if (link(tmp_path, out_path) != 0) {/    if (rename(tmp_path, out_path) != 0) {/' \
  "only the early existence check is left; a file appearing meanwhile is replaced"
mut tool-file-mode $M 's/O_CLOEXEC, 0600);/O_CLOEXEC, 0644);/' \
  "phrase file created readable by everyone"
mut tool-create-wide-then-narrow $M 's/O_CLOEXEC, 0600);/O_CLOEXEC, 0644);/; s/    tmp_created = 1;/    tmp_created = 1; if (fchmod(fd, 0600) != 0) goto done;/' \
  "phrase file created 0644 and narrowed only afterwards"
mut tool-create-not-exclusive $M 's/O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600/O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600/' \
  "temporary file not created exclusively"
mut tool-reads-open-file $M 's/if ((st.st_mode \& 077) != 0) {/if (0) {/' \
  "tool reads a phrase file that other users can read"
mut tool-group-readable $M 's/if ((st.st_mode \& 077) != 0) {/if ((st.st_mode \& 007) != 0) {/' \
  "tool accepts a phrase file readable by its group"
mut tool-owner $M 's/    if (st.st_uid != geteuid()) {/    if (0 \&\& st.st_uid != geteuid()) {/' \
  "tool reads a phrase file that belongs to another user"
mut tool-read-nofollow $M 's/O_RDONLY | O_NOFOLLOW | O_NONBLOCK/O_RDONLY | O_NONBLOCK/' \
  "tool reads a phrase file through a symbolic link"
mut tool-read-nonblock $M 's/O_RDONLY | O_NOFOLLOW | O_NONBLOCK/O_RDONLY | O_NOFOLLOW/' \
  "opening a FIFO as phrase file hangs the tool"
mut tool-regular-file $M 's/if (fstat(fd, \&st) != 0 || !S_ISREG(st.st_mode)) {/if (fstat(fd, \&st) != 0) {/' \
  "tool reads a phrase from something that is not a regular file"
mut tool-nul-check $M 's/    if (strlen(phrase) != got) {/    if (0) {/' \
  "phrase file with an embedded zero byte accepted"
mut tool-size-limit $M 's/if (st.st_size <= 0 || st.st_size > PHRASE_FILE_MAX) {/if (st.st_size <= 0) {/' \
  "phrase file size limit removed (buffer overrun on a large file)"
mut tool-core-dumps $M 's/    setrlimit(RLIMIT_CORE, \&no_core);/    (void)no_core;/; s/    prctl(PR_SET_DUMPABLE, 0);//' \
  "core dumps not switched off"
mut tool-unlink-on-failure $M 's/    if (tmp_created) unlink(tmp_path);/    (void)tmp_created;/' \
  "a half-written file is left behind on failure"
mut tool-unlink-named-on-failure $M 's/    if (rc == 1 \&\& linked) unlink(out_path);/    (void)linked;/' \
  "a phrase file whose directory entry could not be synced is left behind, with no address shown"
mut tool-file-fsync $M 's/        fsync(fd) != 0) {/        0) {/' \
  "phrase file not synced to disk"
mut tool-dir-fsync $M 's/    ok = fsync(fd) == 0;/    ok = 1;/' \
  "directory not synced before the address is shown"
mut tool-stdout-unchecked $M 's/    if (stdout_was_closed) return 0;//; s/    if (fflush(stdout) != 0) return 0;//; s/    return !ferror(stdout);/    return 1;/' \
  "tool reports success although the address could not be written"
mut tool-closed-stdout $M 's/            if (fd == 1) stdout_was_closed = 1;//' \
  "a closed standard output is silently replaced by /dev/null"
mut tool-random-zero $M 's/        if (n == 0) return 0; \/\* a source that gives nothing is broken \*\///' \
  "a random source that returns no bytes hangs the tool"
mut tool-prints-phrase $M 's/printf("address: %s\\n", check.address);/printf("address: %s\\n%s\\n", check.address, phrase);/' \
  "tool prints the recovery phrase"
mut tool-index-ignored $M 's/(uint32_t)index, \&o, \&why) ||/(uint32_t)0, \&o, \&why) ||/' "tool ignores --index"

echo "break-checks: $n faults, $survived not caught"
test "$survived" = 0
