#!/bin/sh
# gz-net between separate local processes: a ping-pong, a member pinned to the
# wrong host key, a member with a known static key, a peer sending unknown
# even and odd messages, a host answering with the wrong sequence number, and
# strict parsing of keys, pins and numbers.
# usage: test_gz_net.sh PATH-TO-GZ-NET PATH-TO-NET-PEER
set -u
B="$1"
P="$2"
T=$(mktemp -d)
LP=
PP=
trap '[ -n "$LP" ] && kill "$LP" 2>/dev/null; [ -n "$PP" ] && kill "$PP" 2>/dev/null; rm -rf "$T"' EXIT
fails=0
ok() { echo "ok   $1"; }
no() { echo "FAIL $1"; fails=$((fails + 1)); }
wait_line() { # FILE: wait for its "listening" line
  i=0
  while ! grep -q '^listening ' "$1" 2>/dev/null; do
    i=$((i + 1)); [ $i -gt 100 ] && return 1
    sleep 0.1
  done
}

HOST_NODE=028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7   # BOLT 8 responder key
HOST_NODE_UPPER=028D7500DD4C12685D1F568B4C2B5048E8534B873319F3A8DAA612B469132EC7F7
MEMBER_NODE=034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa # BOLT 8 initiator key
echo 2121212121212121212121212121212121212121212121212121212121212121 > "$T/host.key"
echo 1111111111111111111111111111111111111111111111111111111111111111 > "$T/member.key"

"$B" listen --port 0 --key-file "$T/host.key" --accept 5 > "$T/out" 2> "$T/err" &
LP=$!
wait_line "$T/out" || { no "listener did not start"; exit 1; }
PORT=$(sed -n 's/^listening \([0-9]*\) .*/\1/p' "$T/out")
grep -qx "listening $PORT $HOST_NODE" "$T/out" && ok "listener reports its key" || no "listener line: $(head -1 "$T/out")"

out=$("$B" connect --port "$PORT" --pin "$HOST_NODE" --count 5 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "ok 5" ] && ok "five pings answered" || no "ping-pong: rc=$rc out=$out"

out=$("$B" connect --port "$PORT" --pin "$MEMBER_NODE" 2>&1); rc=$?
[ $rc -ne 0 ] && [ "$out" = "gz-net: connect: closed by peer" ] && ok "wrong pin refused" || no "wrong pin: rc=$rc out=$out"

out=$("$B" connect --port "$PORT" --pin "$HOST_NODE_UPPER" --key-file "$T/member.key" 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "ok 1" ] && ok "member with a key file, pin in capitals" || no "key file: rc=$rc out=$out"

"$P" even "$PORT" "$HOST_NODE"; rc=$?
[ $rc -eq 0 ] && ok "unknown even message: the host closes" || no "unknown even: net_peer rc=$rc"

"$P" odd "$PORT" "$HOST_NODE"; rc=$?
[ $rc -eq 0 ] && ok "unknown odd message: ignored, the pong still comes" || no "unknown odd: net_peer rc=$rc"

# The listener should now have had its five connections; give it 10 s.
i=0
while kill -0 "$LP" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
kill -0 "$LP" 2>/dev/null && { no "listener still waiting after its connections"; kill "$LP"; }
wait "$LP"; lrc=$?; LP=
[ $lrc -eq 1 ] && ok "listener exits 1 after the refused connections" || no "listener exit $lrc"
sed -n 2p "$T/out" | grep -Eqx 'peer 0[23][0-9a-f]{64}' && ok "first peer has a throwaway key" || no "line 2: $(sed -n 2p "$T/out")"
[ "$(sed -n 3p "$T/out")" = "done 5" ] && ok "done 5" || no "line 3: $(sed -n 3p "$T/out")"
[ "$(sed -n 4p "$T/out")" = "peer $MEMBER_NODE" ] && [ "$(sed -n 5p "$T/out")" = "done 1" ] && ok "second good peer's key reported" || no "lines 4-5: $(sed -n 4,5p "$T/out")"
l6=$(sed -n 6p "$T/out"); l8=$(sed -n 8p "$T/out")
echo "$l6" | grep -Eqx 'peer 0[23][0-9a-f]{64}' && [ "$l6" = "$l8" ] && [ "$(sed -n 7p "$T/out")" = "done 1" ] &&
  [ "$(sed -n 9p "$T/out")" = "done 1" ] && [ "$(wc -l < "$T/out")" -eq 9 ] && ok "the test peer twice, one ping each, nothing else" || no "output: $(cat "$T/out")"
grep -qx 'gz-net: accept: handshake refused (authentication failed)' "$T/err" && ok "host saw act one fail" || no "listener stderr: $(cat "$T/err")"
grep -qx 'gz-net: connection ended: message refused' "$T/err" && [ "$(wc -l < "$T/err")" -eq 2 ] && ok "host reports the unknown even message" || no "listener stderr: $(cat "$T/err")"

# No peer address in the transport's output: the listener's lines name
# connections by key only, and its errors say what failed, not who from.
# Every peer above connected from 127.0.0.1.
if grep -Eq '127\.0\.0\.1|::1|localhost' "$T/out" "$T/err"; then
  no "a peer address appears in the listener's output: $(grep -E '127\.0\.0\.1|::1|localhost' "$T/out" "$T/err")"
else
  ok "no peer address in the listener's output"
fi

# A host that answers with the wrong sequence number.
"$P" badpong > "$T/bp" &
PP=$!
wait_line "$T/bp" || no "badpong did not start"
BPORT=$(sed -n 's/^listening \([0-9]*\) .*/\1/p' "$T/bp"); BNODE=$(sed -n 's/^listening [0-9]* //p' "$T/bp")
out=$("$B" connect --port "$BPORT" --pin "$BNODE" 2>&1); rc=$?
[ $rc -eq 1 ] && [ "$out" = "gz-net: bad pong" ] && ok "wrong pong sequence refused" || no "bad pong: rc=$rc out=$out"
i=0
while kill -0 "$PP" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
kill "$PP" 2>/dev/null; wait "$PP"; PP=

# Strict parsing: each must be refused, as usage (2) or as a bad key file (1).
refused() { # EXPECTED-RC NAME ARGS...
  want=$1; name=$2; shift 2
  "$@" > /dev/null 2>&1; rc=$?
  [ $rc -eq "$want" ] && ok "$name refused" || no "$name: rc=$rc"
}
refused 2 "pin with a sign" "$B" connect --port 1 --pin "+28d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"
refused 2 "pin with a space" "$B" connect --port 1 --pin " 28d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"
refused 2 "short pin" "$B" connect --port 1 --pin 028d75
refused 2 "port 12abc" "$B" connect --port 12abc --pin "$HOST_NODE"
refused 2 "port +5" "$B" connect --port +5 --pin "$HOST_NODE"
refused 2 "port 65536" "$B" listen --port 65536
refused 2 "count 0" "$B" connect --port 1 --pin "$HOST_NODE" --count 0
refused 2 "count 3x" "$B" connect --port 1 --pin "$HOST_NODE" --count 3x
refused 2 "unknown option" "$B" listen --colour blue
printf ' -1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1\n' > "$T/signs.key"
refused 1 "key file of signs" "$B" listen --port 0 --key-file "$T/signs.key" --accept 1
printf '2121212121212121212121212121212121212121212121212121212121212121 extra\n' > "$T/junk.key"
refused 1 "key file with trailing text" "$B" listen --port 0 --key-file "$T/junk.key" --accept 1
printf '212121212121212121212121212121212121212121212121212121212121212\n' > "$T/short.key"
refused 1 "key file one digit short" "$B" listen --port 0 --key-file "$T/short.key" --accept 1

# A key file written on Windows (CRLF line end) is the same key.
printf '2121212121212121212121212121212121212121212121212121212121212121\r\n' > "$T/crlf.key"
"$B" listen --port 0 --key-file "$T/crlf.key" --accept 1 > "$T/crlf.out" 2>&1 &
LP=$!
wait_line "$T/crlf.out" || no "CRLF listener did not start"
CPORT=$(sed -n 's/^listening \([0-9]*\) .*/\1/p' "$T/crlf.out")
grep -qx "listening $CPORT $HOST_NODE" "$T/crlf.out" && ok "key file with CRLF read as the same key" || no "CRLF key: $(cat "$T/crlf.out")"
out=$("$B" connect --port "$CPORT" --pin "$HOST_NODE" 2>&1); [ "$out" = "ok 1" ] || no "CRLF host: $out"
wait "$LP"; LP=

# Names are refused with a message that says why.
out=$("$B" connect --host localhost --port 1 --pin "$HOST_NODE" 2>&1); rc=$?
[ $rc -eq 1 ] && [ "$out" = "gz-net: connect: address must be numeric" ] && ok "connect to a name: address must be numeric" || no "name: rc=$rc out=$out"
out=$("$B" listen --host localhost --port 0 2>&1); rc=$?
[ $rc -eq 1 ] && [ "$out" = "gz-net: cannot listen on localhost:0: address must be numeric" ] && ok "listen on a name: address must be numeric" || no "listen name: rc=$rc out=$out"

[ $fails -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL ($fails)"
[ $fails -eq 0 ]
