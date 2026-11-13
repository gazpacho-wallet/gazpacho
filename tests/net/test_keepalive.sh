#!/bin/sh
# Two processes hold one lobby connection open with BOLT 1 pings and pongs
# (messages.md section 2): gz-net serve as the host, gz-net join as a member
# that sends hello, gets the status and then stays idle.
# usage: test_keepalive.sh GZ_NET SECONDS PING_MS PONG_MS
set -u
B="$1"; SECS="$2"; PING="$3"; PONG="$4"
T=$(mktemp -d)
LP=
trap '[ -n "$LP" ] && kill "$LP" 2>/dev/null; rm -rf "$T"' EXIT
fails=0
"$B" serve --port 0 --accept 1 --ping-ms "$PING" --pong-ms "$PONG" --seconds $((SECS + 60)) > "$T/host" 2>&1 &
LP=$!
i=0
while ! grep -q '^listening ' "$T/host" 2>/dev/null; do
  i=$((i + 1)); [ $i -gt 100 ] && { echo "FAIL: host did not start"; exit 1; }
  sleep 0.1
done
PORT=$(sed -n 's/^listening \([0-9]*\) .*/\1/p' "$T/host")
NODE=$(sed -n 's/^listening [0-9]* \(.*\)$/\1/p' "$T/host")
start=$(date +%s)
"$B" join --port "$PORT" --pin "$NODE" --seconds "$SECS" --ping-ms "$PING" --pong-ms "$PONG" > "$T/member" 2>&1
rc=$?
end=$(date +%s)
wait "$LP"; hrc=$?; LP=
cat "$T/member" "$T/host"
[ $rc -eq 0 ] || { echo "FAIL: member exit $rc"; fails=$((fails + 1)); }
[ $hrc -eq 0 ] || { echo "FAIL: host exit $hrc"; fails=$((fails + 1)); }
grep -q '^status$' "$T/member" || { echo "FAIL: no status"; fails=$((fails + 1)); }
# The stay lasted at least SECS seconds, with pings each way: at least a
# third of the pings a fully idle connection would need.
[ $((end - start)) -ge "$SECS" ] || { echo "FAIL: stay too short"; fails=$((fails + 1)); }
want=$((SECS * 1000 / PING / 3))
mp=$(sed -n 's/^ok pings=[0-9]* pongs=\([0-9]*\)$/\1/p' "$T/member")
hp=$(sed -n 's/^done pings_sent=[0-9]* pongs_received=\([0-9]*\) .*/\1/p' "$T/host")
total=$(( ${mp:-0} + ${hp:-0} ))
[ "$total" -ge "$want" ] || { echo "FAIL: $total pongs in all, wanted $want"; fails=$((fails + 1)); }
grep -q "^closed .* connection lost" "$T/host" || { echo "FAIL: host did not see the member leave"; fails=$((fails + 1)); }
[ $fails -eq 0 ] && echo "RESULT: PASS (${SECS}s, $total pongs)" || echo "RESULT: FAIL ($fails)"
[ $fails -eq 0 ]
