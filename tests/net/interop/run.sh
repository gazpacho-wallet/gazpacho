#!/bin/sh
# Written by the independent reviewer of pull request 10 (2026-11-12),
# from the BOLT 8 text and not from this repository's code; copied here
# unchanged apart from these lines. Opt-in test: -DGZ_INTEROP_PY=ON.
# Reviewer's interop test: gz-net against an independent Python BOLT 8 peer.
# usage: review_py.sh PATH-TO-GZ-NET PATH-TO-bolt8_peer.py
set -u
B="$1"; PY="$2"
T=$(mktemp -d)
LP=
trap '[ -n "$LP" ] && kill "$LP" 2>/dev/null; rm -rf "$T"' EXIT
fails=0
python3 -I "$PY" selftest || fails=$((fails + 1))
echo 2121212121212121212121212121212121212121212121212121212121212121 > "$T/host.key"
"$B" listen --port 0 --key-file "$T/host.key" --accept 1 > "$T/out" 2> "$T/err" &
LP=$!
i=0
while ! grep -q '^listening ' "$T/out" 2>/dev/null; do
  i=$((i + 1)); [ $i -gt 100 ] && { echo "listener did not start"; exit 1; }
  sleep 0.1
done
PORT=$(sed -n 's/^listening \([0-9]*\) .*/\1/p' "$T/out")
NODE=$(sed -n 's/^listening [0-9]* \(.*\)$/\1/p' "$T/out")
python3 -I "$PY" member "$PORT" "$NODE" 1200 || { echo "FAIL member"; fails=$((fails + 1)); }
wait "$LP"; LP=
grep -q '^done 1200$' "$T/out" || { echo "FAIL host output: $(cat "$T/out")"; fails=$((fails + 1)); }

python3 -I "$PY" host 1200 > "$T/pyout" 2>&1 &
LP=$!
i=0
while ! grep -q '^host ' "$T/pyout" 2>/dev/null; do
  i=$((i + 1)); [ $i -gt 100 ] && { echo "py host did not start"; exit 1; }
  sleep 0.1
done
PORT=$(sed -n 's/^host \([0-9]*\) .*/\1/p' "$T/pyout")
NODE=$(sed -n 's/^host [0-9]* \(.*\)$/\1/p' "$T/pyout")
out=$("$B" connect --port "$PORT" --pin "$NODE" --count 1200 2>&1)
[ "$out" = "ok 1200" ] || { echo "FAIL connect: $out"; fails=$((fails + 1)); }
wait "$LP"; rc=$?; LP=
[ $rc -eq 0 ] || { echo "FAIL py host: $(cat "$T/pyout")"; fails=$((fails + 1)); }
cat "$T/pyout"
[ $fails -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL ($fails)"
[ $fails -eq 0 ]
