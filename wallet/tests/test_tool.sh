#!/bin/sh
# Tests for the gz-wallet-keys command-line tool.  usage: test_tool.sh PATH-TO-TOOL
# Uses only throw-away phrases in a temporary directory.
tool="$1"
dir=$(mktemp -d) || exit 1
trap 'rm -rf "$dir"' EXIT
checks=0; failures=0
check() { # check DESCRIPTION COMMAND...
  checks=$((checks + 1)); desc="$1"; shift
  if "$@" >/dev/null 2>&1; then :; else failures=$((failures + 1)); echo "FAIL: $desc"; fi
}
refuse() { # refuse DESCRIPTION COMMAND...   (the command must fail)
  checks=$((checks + 1)); desc="$1"; shift
  if "$@" >/dev/null 2>&1; then failures=$((failures + 1)); echo "FAIL: $desc"; fi
}

# --- verify-vectors ---------------------------------------------------------
"$tool" verify-vectors >"$dir/vv.out" 2>&1; rc=$?
check "verify-vectors exits 0" test "$rc" = 0
check "verify-vectors prints PASS" grep -q '^PASS: all 108 official vectors pass$' "$dir/vv.out"
refuse "verify-vectors prints no FAIL" grep -q FAIL "$dir/vv.out"

# --- mainnet is refused -----------------------------------------------------
"$tool" new --network mainnet --out "$dir/main.phrase" >"$dir/m.out" 2>"$dir/m.err"; rc=$?
check "new refuses mainnet" test "$rc" != 0
check "new says mainnet is refused" grep -q 'refused: mainnet is switched off' "$dir/m.err"
check "new on mainnet creates no file" test ! -e "$dir/main.phrase"
check "new on mainnet prints nothing on stdout" test ! -s "$dir/m.out"

# --- new --------------------------------------------------------------------
"$tool" new --network signet --out "$dir/a.phrase" >"$dir/new.out" 2>"$dir/new.err"; rc=$?
check "new exits 0" test "$rc" = 0
check "new prints exactly two lines" test "$(wc -l <"$dir/new.out")" = 2
check "new prints nothing on stderr" test ! -s "$dir/new.err"
check "line 1 is a signet taproot address" \
  sh -c "sed -n 1p '$dir/new.out' | grep -Eq '^address: tb1p[02-9ac-hj-np-z]{58}\$'"
check "line 2 is the account's extended public key" \
  sh -c "sed -n 2p '$dir/new.out' | grep -Eq \"^account xpub \\(m/86'/1'/0'\\): tpub[1-9A-HJ-NP-Za-km-z]{107}\\\$\""
refuse "new prints no private key" grep -q 'prv' "$dir/new.out"
check "phrase file mode is 0600" test "$(stat -c %a "$dir/a.phrase")" = 600
check "phrase file has 24 words" test "$(wc -w <"$dir/a.phrase")" = 24
check "phrase file is one line" test "$(wc -l <"$dir/a.phrase")" = 1
refuse "the phrase is not in the output" grep -qF "$(cat "$dir/a.phrase")" "$dir/new.out" "$dir/new.err"

# Two runs give two different phrases.
check "second new exits 0" "$tool" new --network signet --out "$dir/b.phrase"
refuse "two phrases differ" cmp -s "$dir/a.phrase" "$dir/b.phrase"

# --- never overwrite --------------------------------------------------------
before=$(sha256sum <"$dir/a.phrase")
"$tool" new --network signet --out "$dir/a.phrase" >"$dir/ow.out" 2>"$dir/ow.err"; rc=$?
check "new refuses an existing file" test "$rc" != 0
check "new says why" grep -q 'never overwritten' "$dir/ow.err"
check "existing file is unchanged" test "$before" = "$(sha256sum <"$dir/a.phrase")"
check "existing file still exists" test -s "$dir/a.phrase"
ln -s "$dir/nowhere" "$dir/link.phrase"
refuse "new refuses to write through a symbolic link" "$tool" new --network signet --out "$dir/link.phrase"
check "nothing was written through the link" test ! -e "$dir/nowhere"

# --- address ----------------------------------------------------------------
"$tool" address --network signet --in "$dir/a.phrase" >"$dir/addr.out" 2>&1; rc=$?
check "address exits 0" test "$rc" = 0
check "address prints three lines" test "$(wc -l <"$dir/addr.out")" = 3
check "address equals the one printed by new" \
  test "$(sed -n 1p "$dir/addr.out")" = "$(sed -n 1p "$dir/new.out")"
check "scriptPubKey is OP_1 and a 32-byte push" \
  sh -c "sed -n 2p '$dir/addr.out' | grep -Eq '^scriptPubKey: 5120[0-9a-f]{64}\$'"
check "path of the first address" test "$(sed -n 3p "$dir/addr.out")" = "path: m/86'/1'/0'/0/0"
refuse "address prints no phrase" grep -qF "$(cat "$dir/a.phrase")" "$dir/addr.out"

"$tool" address --network signet --in "$dir/a.phrase" --index 5 --change >"$dir/addr2.out" 2>&1
check "path with --index and --change" test "$(sed -n 3p "$dir/addr2.out")" = "path: m/86'/1'/0'/1/5"
refuse "another index is another address" \
  test "$(sed -n 1p "$dir/addr2.out")" = "$(sed -n 1p "$dir/addr.out")"
"$tool" address --network regtest --in "$dir/a.phrase" >"$dir/addr3.out" 2>&1
check "regtest prefix" grep -Eq '^address: bcrt1p' "$dir/addr3.out"
refuse "address refuses mainnet" "$tool" address --network mainnet --in "$dir/a.phrase"
refuse "address refuses an unknown network" "$tool" address --network liquid --in "$dir/a.phrase"
refuse "address refuses a bad index" "$tool" address --network signet --in "$dir/a.phrase" --index 2147483648
refuse "address refuses a negative index" "$tool" address --network signet --in "$dir/a.phrase" --index -1
refuse "address refuses a non-number index" "$tool" address --network signet --in "$dir/a.phrase" --index 1x
refuse "address refuses a missing file" "$tool" address --network signet --in "$dir/none"

# The phrase published in BIP 86, on signet.  Reference values computed with
# the Python package embit 0.8.0 (see test_wallet_keys.c).
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' >"$dir/pub.phrase"
chmod 600 "$dir/pub.phrase"
"$tool" address --network signet --in "$dir/pub.phrase" >"$dir/pub.out" 2>&1
check "known phrase, known signet address" \
  test "$(sed -n 1p "$dir/pub.out")" = "address: tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj"
check "known phrase, known scriptPubKey" \
  test "$(sed -n 2p "$dir/pub.out")" = "scriptPubKey: 51203b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786"
"$tool" address --network testnet4 --in "$dir/pub.phrase" --index 7 >"$dir/pub7.out" 2>&1
check "known phrase, index 7" \
  test "$(sed -n 1p "$dir/pub7.out")" = "address: tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"

# --- bad phrase files -------------------------------------------------------
chmod 644 "$dir/pub.phrase"
refuse "a phrase file readable by others is refused" "$tool" address --network signet --in "$dir/pub.phrase"
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon' >"$dir/bad.phrase"
chmod 600 "$dir/bad.phrase"
"$tool" address --network signet --in "$dir/bad.phrase" >"$dir/bad.out" 2>&1; rc=$?
check "a phrase with a wrong checksum is refused" test "$rc" != 0
check "the reason is given" grep -q 'checksum' "$dir/bad.out"
refuse "the refusal does not repeat the phrase" grep -q 'abandon' "$dir/bad.out"
: >"$dir/empty.phrase"; chmod 600 "$dir/empty.phrase"
refuse "an empty phrase file is refused" "$tool" address --network signet --in "$dir/empty.phrase"

# --- usage ------------------------------------------------------------------
refuse "no command" "$tool"
refuse "unknown command" "$tool" export
refuse "new without --out" "$tool" new --network signet
refuse "new without --network" "$tool" new --out "$dir/c.phrase"
check "new without --network creates no file" test ! -e "$dir/c.phrase"

echo "test_tool: $checks checks, $failures failed"
test "$failures" = 0
