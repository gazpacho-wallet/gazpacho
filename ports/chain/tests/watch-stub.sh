#!/usr/bin/env bash
# Runs the chain worker against the scripted Esplora stub on this machine
# (127.0.0.1). Called by ctest (test chain_watch_stub).
#
#   watch-stub.sh STUB_TEST TESTS_DIR WORK_DIR
#
# Exit 0 pass, 1 fail, 77 skipped (python3 missing).
set -u
test=$1 tests=$2 work=$3
command -v python3 >/dev/null 2>&1 || { echo "python3 not found: skipped"; exit 77; }
mkdir -p "$(dirname "$work")" || exit 1
work=$(mktemp -d "$work.XXXXXX") || exit 1
stub=
cleanup() {
  [ -n "$stub" ] && kill "$stub" 2>/dev/null
  wait 2>/dev/null
  cd / && rm -rf "$work"
}
trap cleanup EXIT
python3 -I "$tests/watch_stub.py" "$work" 2>"$work/stub.err" &
stub=$!
for _ in $(seq 1 100); do [ -f "$work/stub.port" ] && break; sleep 0.1; done
[ -f "$work/stub.port" ] || { echo "the stub did not start"; cat "$work/stub.err"; exit 1; }
"$test" "$(cat "$work/stub.port")" "$work"
status=$?
[ -s "$work/stub.err" ] && { echo "the stub wrote errors:"; head -20 "$work/stub.err"; status=1; }
exit $status
