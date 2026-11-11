#!/bin/sh
# Tests for the gz-wallet-keys command-line tool.  usage: test_tool.sh PATH-TO-TOOL
# Uses only throw-away phrases in a temporary directory.
#
# Patterns here are matched against output that contains random addresses and
# keys, so every pattern is anchored or long enough that random text cannot
# match it by chance.
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
# An extended private key as text: xprv/tprv followed by 107 Base58 characters.
PRV='[xt]prv[1-9A-HJ-NP-Za-km-z]{107}'
PUB_PHRASE='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
no_temp() { ! ls -a "$dir" | grep -q '\.tmp-'; }

# --- verify-vectors ---------------------------------------------------------
"$tool" verify-vectors >"$dir/vv.out" 2>&1; rc=$?
check "verify-vectors exits 0" test "$rc" = 0
check "verify-vectors prints PASS" grep -q '^PASS: all 162 official vectors pass$' "$dir/vv.out"
refuse "verify-vectors prints no FAIL" grep -q '^FAIL' "$dir/vv.out"
check "verify-vectors prints 14 groups" test "$(grep -c '^pass ' "$dir/vv.out")" = 14
refuse "verify-vectors takes no arguments" "$tool" verify-vectors --network mainnet
"$tool" verify-vectors >/dev/full 2>/dev/null; rc=$?
check "verify-vectors fails when its output cannot be written" test "$rc" != 0

# --- mainnet is refused -----------------------------------------------------
"$tool" new --network mainnet --out "$dir/main.phrase" >"$dir/m.out" 2>"$dir/m.err"; rc=$?
check "new refuses mainnet" test "$rc" != 0
check "new says mainnet is refused" grep -q '^refused: mainnet is switched off' "$dir/m.err"
check "new on mainnet creates no file" test ! -e "$dir/main.phrase"
check "new on mainnet prints nothing on stdout" test ! -s "$dir/m.out"
"$tool" new --network signet --network mainnet --out "$dir/main2.phrase" >/dev/null 2>"$dir/m2.err"; rc=$?
check "mainnet given second is refused too" test "$rc" != 0
check "and creates no file" test ! -e "$dir/main2.phrase"
for n in Mainnet MAINNET main bitcoin livenet bc 0 ""; do
  refuse "network name [$n] is not accepted" "$tool" new --network "$n" --out "$dir/main3.phrase"
  check "network name [$n] creates no file" test ! -e "$dir/main3.phrase"
done

# --- new --------------------------------------------------------------------
"$tool" new --network signet --out "$dir/a.phrase" >"$dir/new.out" 2>"$dir/new.err"; rc=$?
check "new exits 0" test "$rc" = 0
check "new prints exactly two lines" test "$(wc -l <"$dir/new.out")" = 2
check "new prints nothing on stderr" test ! -s "$dir/new.err"
check "line 1 is a signet taproot address" \
  sh -c "sed -n 1p '$dir/new.out' | grep -Eq '^address: tb1p[02-9ac-hj-np-z]{58}\$'"
check "line 2 is the account's extended public key" \
  sh -c "sed -n 2p '$dir/new.out' | grep -Eq \"^account xpub \\(m/86'/1'/0'\\): tpub[1-9A-HJ-NP-Za-km-z]{107}\\\$\""
check "the private-key pattern recognises a private key" \
  sh -c "printf 'key: tprv%0107d\n' 0 | tr 0 A | grep -Eq '$PRV'"
refuse "the private-key pattern does not match a public key or loose letters" \
  sh -c "printf 'tpub%0107d prv tprv%050d\n' 0 0 | tr 0 A | grep -Eq '$PRV'"
refuse "new prints no private key" grep -Eq "$PRV" "$dir/new.out" "$dir/new.err"
check "phrase file mode is 0600" test "$(stat -c %a "$dir/a.phrase")" = 600
check "phrase file has one name" test "$(stat -c %h "$dir/a.phrase")" = 1
check "phrase file has 24 words" test "$(wc -w <"$dir/a.phrase")" = 24
check "phrase file is one line" test "$(wc -l <"$dir/a.phrase")" = 1
refuse "the phrase is not in the output" grep -qF "$(cat "$dir/a.phrase")" "$dir/new.out" "$dir/new.err"
refuse "the start of the phrase is not in the output" grep -qF "$(cut -d' ' -f1-4 "$dir/a.phrase")" "$dir/new.out" "$dir/new.err"
check "no temporary file is left" no_temp

# Two runs give two different phrases.
check "second new exits 0" "$tool" new --network signet --out "$dir/b.phrase"
refuse "two phrases differ" cmp -s "$dir/a.phrase" "$dir/b.phrase"

# The file is owner-only whatever the umask.
(umask 000; "$tool" new --network signet --out "$dir/u0.phrase" >/dev/null 2>&1)
check "umask 000 still gives mode 0600" test "$(stat -c %a "$dir/u0.phrase")" = 600
(umask 077; "$tool" new --network regtest --out "$dir/u7.phrase" >"$dir/u7.out" 2>&1)
check "umask 077 gives mode 0600" test "$(stat -c %a "$dir/u7.phrase")" = 600
check "regtest address from new" grep -Eq '^address: bcrt1p[02-9ac-hj-np-z]{58}$' "$dir/u7.out"

# --- never overwrite --------------------------------------------------------
before=$(sha256sum <"$dir/a.phrase")
"$tool" new --network signet --out "$dir/a.phrase" >"$dir/ow.out" 2>"$dir/ow.err"; rc=$?
check "new refuses an existing file" test "$rc" != 0
check "new says why" grep -q 'never overwritten' "$dir/ow.err"
check "new prints no address when it refuses" test ! -s "$dir/ow.out"
check "existing file is unchanged" test "$before" = "$(sha256sum <"$dir/a.phrase")"
check "existing file still exists" test -s "$dir/a.phrase"
ln -s "$dir/nowhere" "$dir/link.phrase"
refuse "new refuses to write through a symbolic link" "$tool" new --network signet --out "$dir/link.phrase"
check "nothing was written through the link" test ! -e "$dir/nowhere"
ln -s "$dir/a.phrase" "$dir/tolive.phrase"
refuse "new refuses a symbolic link to an existing file" "$tool" new --network signet --out "$dir/tolive.phrase"
check "the file behind the link is unchanged" test "$before" = "$(sha256sum <"$dir/a.phrase")"
mkdir "$dir/adir"
refuse "new refuses a directory as output" "$tool" new --network signet --out "$dir/adir"
refuse "new fails in a directory that does not exist" "$tool" new --network signet --out "$dir/nodir/x.phrase"
check "still no temporary file is left" no_temp

# --- the address could not be delivered --------------------------------------
"$tool" new --network signet --out "$dir/full.phrase" >/dev/full 2>"$dir/full.err"; rc=$?
check "new with a full standard output exits 3" test "$rc" = 3
check "and says the file was written" grep -q '^error: the phrase file was written' "$dir/full.err"
check "and the file is complete" "$tool" address --network signet --in "$dir/full.phrase"
"$tool" new --network signet --out "$dir/closed.phrase" >&- 2>"$dir/closed.err"; rc=$?
check "new with a closed standard output exits 3" test "$rc" = 3
check "and the file is complete and holds only the phrase" test "$(wc -w <"$dir/closed.phrase")" = 24
check "and the file gives an address" "$tool" address --network signet --in "$dir/closed.phrase"
"$tool" address --network signet --in "$dir/a.phrase" >/dev/full 2>/dev/null; rc=$?
check "address with a full standard output fails" test "$rc" != 0
"$tool" address --network signet --in "$dir/a.phrase" >&- 2>/dev/null; rc=$?
check "address with a closed standard output fails" test "$rc" != 0

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
refuse "address prints no private key" grep -Eq "$PRV" "$dir/addr.out"

"$tool" address --network signet --in "$dir/a.phrase" --index 5 --change >"$dir/addr2.out" 2>&1
check "path with --index and --change" test "$(sed -n 3p "$dir/addr2.out")" = "path: m/86'/1'/0'/1/5"
refuse "another index is another address" \
  test "$(sed -n 1p "$dir/addr2.out")" = "$(sed -n 1p "$dir/addr.out")"
"$tool" address --network regtest --in "$dir/a.phrase" >"$dir/addr3.out" 2>&1
check "regtest prefix" grep -Eq '^address: bcrt1p[02-9ac-hj-np-z]{58}$' "$dir/addr3.out"
refuse "address refuses mainnet" "$tool" address --network mainnet --in "$dir/a.phrase"
refuse "address refuses an unknown network" "$tool" address --network liquid --in "$dir/a.phrase"
refuse "address refuses a bad index" "$tool" address --network signet --in "$dir/a.phrase" --index 2147483648
refuse "address refuses a negative index" "$tool" address --network signet --in "$dir/a.phrase" --index -1
refuse "address refuses a non-number index" "$tool" address --network signet --in "$dir/a.phrase" --index 1x
refuse "address refuses a hexadecimal index" "$tool" address --network signet --in "$dir/a.phrase" --index 0x10
refuse "address refuses an empty index" "$tool" address --network signet --in "$dir/a.phrase" --index ""
refuse "address refuses a missing file" "$tool" address --network signet --in "$dir/none"
refuse "address refuses a missing network" "$tool" address --in "$dir/a.phrase"
for o in --verbose --debug --show-phrase --xprv --help; do
  refuse "unknown option $o is refused" "$tool" address --network signet --in "$dir/a.phrase" $o
done

# The phrase published in BIP 86, on the test networks.  Reference values
# computed with the Python package embit 0.8.0 (see test_wallet_keys.c).
printf '%s\n' "$PUB_PHRASE" >"$dir/pub.phrase"
chmod 600 "$dir/pub.phrase"
REF='address: tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj'
"$tool" address --network signet --in "$dir/pub.phrase" >"$dir/pub.out" 2>&1
check "known phrase, known signet address" test "$(sed -n 1p "$dir/pub.out")" = "$REF"
check "known phrase, known scriptPubKey" \
  test "$(sed -n 2p "$dir/pub.out")" = "scriptPubKey: 51203b82b2b2a9185315da6f80da5f06d0440d8a5e1457fa93387c2d919c86ec8786"
"$tool" address --network testnet4 --in "$dir/pub.phrase" --index 7 >"$dir/pub7.out" 2>&1
check "known phrase, index 7, testnet4" \
  test "$(sed -n 1p "$dir/pub7.out")" = "address: tb1pyfv094rr0vk28lf8v9yx3veaacdzg26ztqk4ga84zucqqhafnn5q9my9rz"
# testnet and testnet4 are separate network names; both are accepted, and
# today both give the same address as signet (same prefix, same coin type).
for n in testnet testnet4; do
  "$tool" address --network $n --in "$dir/pub.phrase" >"$dir/$n.out" 2>&1; rc=$?
  check "$n is accepted" test "$rc" = 0
  check "$n gives the shared test-network address" test "$(sed -n 1p "$dir/$n.out")" = "$REF"
done
refuse "testnet3 is not a network name" "$tool" address --network testnet3 --in "$dir/pub.phrase"
refuse "testnet-4 is not a network name" "$tool" address --network testnet-4 --in "$dir/pub.phrase"

# Harmless differences in white space give the same address.
sed 's/$/\r/' "$dir/pub.phrase" >"$dir/crlf"; tr ' ' '\t' <"$dir/pub.phrase" >"$dir/tabs"
tr ' ' '\n' <"$dir/pub.phrase" >"$dir/lines"; (echo; echo; cat "$dir/pub.phrase"; echo) >"$dir/blank"
printf '%s' "$PUB_PHRASE" >"$dir/nonl"; sed 's/ /  /g' "$dir/pub.phrase" >"$dir/dbl"
for f in crlf tabs lines blank nonl dbl; do
  chmod 600 "$dir/$f"
  check "white space variant $f gives the same address" \
    test "$("$tool" address --network signet --in "$dir/$f" 2>/dev/null | sed -n 1p)" = "$REF"
done
tr a-z A-Z <"$dir/pub.phrase" >"$dir/upper"; chmod 600 "$dir/upper"
refuse "an upper-case phrase is refused" "$tool" address --network signet --in "$dir/upper"
(cat "$dir/pub.phrase"; echo abandon) >"$dir/extra"; chmod 600 "$dir/extra"
refuse "a phrase with an extra word is refused" "$tool" address --network signet --in "$dir/extra"

# --- phrase files the tool must not read --------------------------------------
# Modes: nobody but the owner may have any access.
for m in 644 640 604 660 620 602 610 601; do
  cp "$dir/pub.phrase" "$dir/m$m"; chmod $m "$dir/m$m"
  "$tool" address --network signet --in "$dir/m$m" >"$dir/mode.out" 2>"$dir/mode.err"; rc=$?
  check "a phrase file of mode $m is refused" test "$rc" != 0
  check "mode $m: the reason is given" grep -q '^refused: the phrase file can be read by other users' "$dir/mode.err"
  check "mode $m: no address is printed" test ! -s "$dir/mode.out"
done
for m in 600 400; do
  cp "$dir/pub.phrase" "$dir/m$m"; chmod $m "$dir/m$m"
  check "a phrase file of mode $m is read" "$tool" address --network signet --in "$dir/m$m"
done
# A symbolic link to a good file.
ln -s "$dir/pub.phrase" "$dir/in-link"
"$tool" address --network signet --in "$dir/in-link" >"$dir/sl.out" 2>"$dir/sl.err"; rc=$?
check "a phrase file reached through a symbolic link is refused" test "$rc" != 0
check "symbolic link: the reason is given" grep -q '^refused: the phrase file is a symbolic link' "$dir/sl.err"
check "symbolic link: no address is printed" test ! -s "$dir/sl.out"
# Things that are not regular files.  The FIFO must not make the tool wait.
"$tool" address --network signet --in "$dir/adir" >/dev/null 2>"$dir/nr.err"; rc=$?
check "a directory is refused" test "$rc" != 0
check "directory: the reason is given" grep -q '^refused: the phrase file is not a regular file' "$dir/nr.err"
mkfifo "$dir/fifo"; chmod 600 "$dir/fifo"
timeout 10 "$tool" address --network signet --in "$dir/fifo" >/dev/null 2>"$dir/fifo.err"; rc=$?
check "a FIFO does not hang the tool" test "$rc" != 124
check "a FIFO is refused" test "$rc" = 1
check "FIFO: the reason is given" grep -q '^refused: the phrase file is not a regular file' "$dir/fifo.err"
# A zero byte inside the file.
printf '%s\0\n' "$PUB_PHRASE" >"$dir/nul"; chmod 600 "$dir/nul"
"$tool" address --network signet --in "$dir/nul" >"$dir/nul.out" 2>"$dir/nul.err"; rc=$?
check "a phrase file with a zero byte is refused" test "$rc" != 0
check "zero byte: the reason is given" grep -q '^refused: the phrase file is not text' "$dir/nul.err"
check "zero byte: no address is printed" test ! -s "$dir/nul.out"
# Too large: a valid phrase followed by white space past the limit.  Without
# the limit this would overrun the tool's buffer.
(printf '%s\n' "$PUB_PHRASE"; head -c 2000 /dev/zero | tr '\0' '\n') >"$dir/big"; chmod 600 "$dir/big"
"$tool" address --network signet --in "$dir/big" >"$dir/big.out" 2>"$dir/big.err"; rc=$?
check "a phrase file over the size limit is refused" test "$rc" = 1
check "size limit: the reason is given" grep -q '^refused: the phrase file is empty or too large' "$dir/big.err"
check "size limit: no address is printed" test ! -s "$dir/big.out"
(printf '%s' "$PUB_PHRASE"; head -c 931 /dev/zero | tr '\0' '\n') >"$dir/max"; chmod 600 "$dir/max"
check "a phrase file of exactly 1024 bytes is read" test "$(wc -c <"$dir/max")" = 1024
check "and gives the address" test "$("$tool" address --network signet --in "$dir/max" 2>/dev/null | sed -n 1p)" = "$REF"
(cat "$dir/max"; echo) >"$dir/max1"; chmod 600 "$dir/max1"
refuse "a phrase file of 1025 bytes is refused" "$tool" address --network signet --in "$dir/max1"
: >"$dir/empty.phrase"; chmod 600 "$dir/empty.phrase"
refuse "an empty phrase file is refused" "$tool" address --network signet --in "$dir/empty.phrase"
# Another user's file (only root can make one; test_tool_faults.sh covers the
# rule for everyone else).
if [ "$(id -u)" = 0 ]; then
  cp "$dir/pub.phrase" "$dir/other"; chmod 600 "$dir/other"; chown 65534 "$dir/other"
  "$tool" address --network signet --in "$dir/other" >/dev/null 2>"$dir/other.err"; rc=$?
  check "another user's phrase file is refused" test "$rc" != 0
  check "other user: the reason is given" grep -q '^refused: the phrase file belongs to another user' "$dir/other.err"
fi
# A wrong checksum.
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon' >"$dir/bad.phrase"
chmod 600 "$dir/bad.phrase"
"$tool" address --network signet --in "$dir/bad.phrase" >"$dir/bad.out" 2>&1; rc=$?
check "a phrase with a wrong checksum is refused" test "$rc" != 0
check "the reason is given" grep -q 'the checksum does not match' "$dir/bad.out"
refuse "the refusal does not repeat the phrase" grep -q 'abandon' "$dir/bad.out"

# --- usage ------------------------------------------------------------------
refuse "no command" "$tool"
refuse "unknown command" "$tool" export
refuse "new without --out" "$tool" new --network signet
refuse "new without --network" "$tool" new --out "$dir/c.phrase"
check "new without --network creates no file" test ! -e "$dir/c.phrase"
refuse "new with --in" "$tool" new --network signet --out "$dir/c.phrase" --in "$dir/a.phrase"
check "new with --in creates no file" test ! -e "$dir/c.phrase"
check "no temporary file is left at the end" no_temp

echo "test_tool: $checks checks, $failures failed"
test "$failures" = 0
