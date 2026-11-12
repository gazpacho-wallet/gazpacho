#!/bin/sh
# gz-net between separate local processes: a ping-pong, a member pinned to the
# wrong host key, and a member with a known static key.
# usage: test_gz_net.sh PATH-TO-GZ-NET
set -u
B="$1"
T=$(mktemp -d)
LP=
trap '[ -n "$LP" ] && kill "$LP" 2>/dev/null; rm -rf "$T"' EXIT
fails=0
ok() { echo "ok   $1"; }
no() { echo "FAIL $1"; fails=$((fails + 1)); }

HOST_NODE=028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7   # BOLT 8 responder key
MEMBER_NODE=034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa # BOLT 8 initiator key
echo 2121212121212121212121212121212121212121212121212121212121212121 > "$T/host.key"
echo 1111111111111111111111111111111111111111111111111111111111111111 > "$T/member.key"

"$B" listen --port 0 --key-file "$T/host.key" --accept 3 > "$T/out" 2> "$T/err" &
LP=$!
i=0
while ! grep -q '^listening ' "$T/out" 2>/dev/null; do
  i=$((i + 1)); [ $i -gt 100 ] && { no "listener did not start"; exit 1; }
  sleep 0.1
done
PORT=$(sed -n 's/^listening \([0-9]*\) .*/\1/p' "$T/out")
grep -qx "listening $PORT $HOST_NODE" "$T/out" && ok "listener reports its key" || no "listener line: $(head -1 "$T/out")"

out=$("$B" connect --port "$PORT" --pin "$HOST_NODE" --count 5 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "ok 5" ] && ok "five pings answered" || no "ping-pong: rc=$rc out=$out"

out=$("$B" connect --port "$PORT" --pin "$MEMBER_NODE" 2>&1); rc=$?
[ $rc -ne 0 ] && [ "$out" = "gz-net: connect: closed by peer" ] && ok "wrong pin refused" || no "wrong pin: rc=$rc out=$out"

out=$("$B" connect --port "$PORT" --pin "$HOST_NODE" --key-file "$T/member.key" 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "ok 1" ] && ok "member with a key file" || no "key file: rc=$rc out=$out"

wait "$LP"; lrc=$?; LP=
[ $lrc -eq 1 ] && ok "listener exits 1 after the refused connection" || no "listener exit $lrc"
sed -n 2p "$T/out" | grep -Eqx 'peer 0[23][0-9a-f]{64}' && ok "first peer has a throwaway key" || no "line 2: $(sed -n 2p "$T/out")"
[ "$(sed -n 3p "$T/out")" = "done 5" ] && ok "done 5" || no "line 3: $(sed -n 3p "$T/out")"
[ "$(sed -n 4p "$T/out")" = "peer $MEMBER_NODE" ] && ok "second good peer's key reported" || no "line 4: $(sed -n 4p "$T/out")"
[ "$(sed -n 5p "$T/out")" = "done 1" ] && [ "$(wc -l < "$T/out")" -eq 5 ] && ok "done 1, nothing else" || no "output: $(cat "$T/out")"
grep -qx 'gz-net: accept: handshake refused (authentication failed)' "$T/err" && ok "host saw act one fail" || no "listener stderr: $(cat "$T/err")"

out=$("$B" connect --port 1 --pin zz 2>&1); rc=$?
[ $rc -eq 2 ] && ok "bad pin refused as usage" || no "usage: rc=$rc"

[ $fails -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL ($fails)"
[ $fails -eq 0 ]
