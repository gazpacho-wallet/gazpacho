#!/bin/sh
# Fault-injection tests for gz-wallet-keys.
# usage: test_tool_faults.sh PATH-TO-gz-wallet-keys-faults PATH-TO-gz-wallet-keys
#
# The first program is the tool built with tests/tool_faults.c, which can make
# its system calls fail on request (environment variable GZ_FAULT).  The
# second is the ordinary tool, used to read back what the first one wrote.
# Throw-away phrases only, in a temporary directory.
faulty="$1"; tool="$2"
dir=$(mktemp -d) || exit 1
trap 'rm -rf "$dir"' EXIT
checks=0; failures=0
check() {
  checks=$((checks + 1)); desc="$1"; shift
  if "$@" >/dev/null 2>&1; then :; else failures=$((failures + 1)); echo "FAIL: $desc"; fi
}
refuse() {
  checks=$((checks + 1)); desc="$1"; shift
  if "$@" >/dev/null 2>&1; then failures=$((failures + 1)); echo "FAIL: $desc"; fi
}
temps() { ls -a "$dir" | grep -c '\.tmp-'; }
run_new() { # run_new FAULT FILE  -> sets rc; stdout in $dir/o, stderr in $dir/e
  GZ_FAULT="$1" timeout 10 "$faulty" new --network signet --out "$dir/$2" >"$dir/o" 2>"$dir/e"; rc=$?
}

# --- the wrappers are in use, and the tool makes the calls it should ----------
run_new wrap_report w.phrase
check "wrap_report: new succeeds" test "$rc" = 0
for call in getrandom open-create write fsync-file read geteuid link fsync-directory; do
  check "the tool's $call goes through the wrapper" grep -q "^wrapped: $call\$" "$dir/e"
done
# Order: the file is synced, then named, then the directory is synced.
order=$(grep -E '^wrapped: (fsync-file|link|fsync-directory)$' "$dir/e" | tr '\n' ' ')
check "sync file, then name it, then sync the directory" test "$order" = "wrapped: fsync-file wrapped: link wrapped: fsync-directory "
check "without a fault the faulty build behaves like the tool" \
  test "$(sed -n 1p "$dir/o")" = "$("$tool" address --network signet --in "$dir/w.phrase" | sed -n 1p)"

# --- faults that must make "new" fail and leave nothing behind ---------------
for f in rand_fail rand_zero write_enospc write_late fsync_file_fail fsync_dir_fail link_fail; do
  run_new $f f.phrase
  check "$f: new fails" test "$rc" = 1
  check "$f: no phrase file is left" test ! -e "$dir/f.phrase"
  check "$f: no temporary file is left" test "$(temps)" = 0
  check "$f: no address is printed" test ! -s "$dir/o"
  check "$f: an error is reported" grep -q '^error: ' "$dir/e"
done

# --- faults the tool must ride out --------------------------------------------
for f in rand_short write_short write_eintr read_short read_eintr; do
  rm -f "$dir/g.phrase"
  run_new $f g.phrase
  check "$f: new succeeds" test "$rc" = 0
  check "$f: the file has 24 words" test "$(wc -w <"$dir/g.phrase")" = 24
  check "$f: the address printed is the address of the file" \
    test "$(sed -n 1p "$dir/o")" = "$("$tool" address --network signet --in "$dir/g.phrase" | sed -n 1p)"
  check "$f: no temporary file is left" test "$(temps)" = 0
done

# --- killed part-way: the name is never taken by a half-written file ----------
run_new die_in_write k.phrase
check "die_in_write: the process died" test "$rc" = 137
check "die_in_write: the phrase file does not exist" test ! -e "$dir/k.phrase"
check "die_in_write: no address was printed" test ! -s "$dir/o"
check "die_in_write: only a temporary file is left" test "$(temps)" = 1
run_new none k.phrase
check "after die_in_write the same name can be used" test "$rc" = 0
check "and the file is complete" test "$(wc -w <"$dir/k.phrase")" = 24
rm -f "$dir"/*.tmp-*
run_new die_in_link l.phrase
check "die_in_link: the process died" test "$rc" = 137
check "die_in_link: the phrase file does not exist" test ! -e "$dir/l.phrase"
check "die_in_link: no address was printed" test ! -s "$dir/o"
check "die_in_link: the temporary file is owner-only" \
  test "$(stat -c %a "$dir"/l.phrase.tmp-*)" = 600
run_new none l.phrase
check "after die_in_link the same name can be used" test "$rc" = 0
rm -f "$dir"/*.tmp-*

# --- a file that appears under the name at the last moment is not replaced ----
run_new race_create r.phrase
check "race_create: new fails" test "$rc" = 1
check "race_create: the reason is given" grep -q 'never overwritten' "$dir/e"
check "race_create: the other file is untouched" test "$(cat "$dir/r.phrase")" = "theirs"
check "race_create: no address is printed" test ! -s "$dir/o"
check "race_create: no temporary file is left" test "$(temps)" = 0

# --- how the file is created --------------------------------------------------
run_new check_create c.phrase
check "the file is created exclusively, with mode 0600 and without following links" test "$rc" = 0
check "check_create: the file exists" test -s "$dir/c.phrase"

# --- core dumps are off before any secret exists ------------------------------
run_new check_core d.phrase
check "core dumps are switched off before the random source is read" test "$rc" = 0
GZ_FAULT=check_core "$faulty" address --network signet --in "$dir/c.phrase" >/dev/null 2>&1; rc=$?
check "also for the address command" test "$rc" = 0

# --- a phrase file of another user --------------------------------------------
GZ_FAULT=other_uid "$faulty" address --network signet --in "$dir/c.phrase" >"$dir/o" 2>"$dir/e"; rc=$?
check "a phrase file owned by another user is refused" test "$rc" = 1
check "other user: the reason is given" grep -q '^refused: the phrase file belongs to another user' "$dir/e"
check "other user: no address is printed" test ! -s "$dir/o"
GZ_FAULT=none "$faulty" address --network signet --in "$dir/c.phrase" >/dev/null 2>&1; rc=$?
check "the owner's own file is read" test "$rc" = 0

echo "test_tool_faults: $checks checks, $failures failed"
test "$failures" = 0
