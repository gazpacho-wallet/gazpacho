#!/usr/bin/env bash
# Runs the transport test and the gz-chain tool tests against servers on
# this machine only (127.0.0.1). Called by ctest (test chain_local_servers,
# label "slow").
#
#   local-servers.sh TRANSPORT_TEST GZ_CHAIN TESTS_DIR WORK_DIR
#
# Exit 0 pass, 1 fail, 77 skipped (python3 or openssl missing).
set -u
transport=$1 tool=$2 tests=$3 work=$4
command -v python3 >/dev/null 2>&1 || { echo "python3 not found: skipped"; exit 77; }
command -v openssl >/dev/null 2>&1 || { echo "openssl not found: skipped"; exit 77; }

rm -rf "$work" && mkdir -p "$work" || exit 1
cd "$work" || exit 1
fail=0
server=

cleanup() { [ -n "$server" ] && kill "$server" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

# --- certificates: a test authority, a good one, one for another name, a self-signed one
q() { "$@" >/dev/null 2>&1 || { echo "certificate step failed: $*"; exit 1; }; }
q openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=gz-test-ca" \
  -keyout ca.key -out ca.pem
for name in good:localhost wrongname:not-this-host.test; do
  f=${name%%:*} cn=${name#*:}
  q openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" -keyout $f.key -out $f.csr
  printf "subjectAltName=DNS:%s\n" "$cn" > $f.ext
  q openssl x509 -req -in $f.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile $f.ext -out $f.pem
done
q openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" -keyout selfsigned.key -out selfsigned.pem

# --- the servers
python3 -I "$tests/local_server.py" "$work" "$tests/data" 2>server.err &
server=$!
for _ in $(seq 1 100); do [ -f ports ] && break; sleep 0.1; done
[ -f ports ] || { echo "local servers did not start"; cat server.err; exit 1; }
. ./ports
H=http://127.0.0.1:$HTTP_PORT

# --- 1. the transport itself
"$transport" "$HTTP_PORT" "$GOOD_PORT" "$WRONGNAME_PORT" "$SELFSIGNED_PORT" "$work/ca.pem" || fail=1

# --- 2. the tool, end to end through real HTTP
expect() { # expect NAME WANT_EXIT REGEX command...
  local name=$1 want=$2 re=$3; shift 3
  out=$("$@" 2>&1); got=$?
  if [ "$got" != "$want" ] || ! printf '%s\n' "$out" | grep -Eq -- "$re"; then
    echo "FAIL $name: exit $got (wanted $want)"; printf '%s\n' "$out" | sed 's/^/    /'; fail=1
  else
    echo "ok   $name"
  fi
}
TXA=8690387a65262437580d45b77f1cb0792faff46cecb72c5ee22390e5193a6c9a
TXN=0000000000000000000000000000000000000000000000000000000000000001

expect "two honest servers agree on the tip" 0 "verdict: ok .servers of 2 operators" \
  "$tool" --server $H/honest --server http://localhost:$HTTP_PORT/honest2 tip
expect "proof of a real transaction exits 0" 0 "2 confirmation\(s\) checked" \
  "$tool" --server $H/honest --server http://localhost:$HTTP_PORT/honest2 proof $TXA
expect "proof of an unknown transaction exits 1" 1 "unknown to the server" \
  "$tool" --server $H/honest --server http://localhost:$HTTP_PORT/honest2 proof $TXN
expect "a server hiding a transaction: disagreement exits 1" 1 "contradict each other" \
  "$tool" --server $H/honest --server http://localhost:$HTTP_PORT/hider tx $TXA
expect "one server only: never 'agree'" 1 "fewer than two operators" \
  "$tool" --server $H/honest tip
if printf '%s' "$out" | grep -q "operators give this answer"; then
  echo "FAIL one server only printed an agreed answer"; fail=1
fi
expect "the same server twice is refused" 2 "cannot be compared with itself" \
  "$tool" --server $H/honest --server $H/honest tip
expect "two paths on one host are refused" 2 "cannot be compared with itself" \
  "$tool" --server $H/honest --server $H/honest2 tip
expect "plain http to a public address is refused" 2 "not a usable server address" \
  "$tool" --server http://mempool.space/signet/api --server $H/honest tip
expect "a mainnet server under --network signet is not counted" 1 "wrong-network" \
  "$tool" --server $H/honest --server http://localhost:$HTTP_PORT/mainnet tip
: > posts.log
expect "broadcast is refused when a server is on mainnet, whatever the flag" 2 "is a mainnet server" \
  "$tool" --network signet --server $H/honest --server http://localhost:$HTTP_PORT/mainnet \
  broadcast "$(cat "$tests/data/tx_a_hex.txt")"
if [ -s posts.log ]; then echo "FAIL a transaction was posted to a server"; cat posts.log; fail=1; fi
expect "broadcast --network mainnet is refused before any request" 2 "refusing to broadcast on mainnet" \
  "$tool" --network mainnet --server $H/honest broadcast "$(cat "$tests/data/tx_a_hex.txt")"
if [ -s posts.log ]; then echo "FAIL a transaction was posted to a server"; fail=1; fi
expect "fee on signet uses 0.1 sat/vB" 0 "0.100 sat/vB, the fixed test-network rate" \
  "$tool" --server $H/honest --server http://localhost:$HTTP_PORT/honest2 fee

exit $fail
