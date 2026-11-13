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

# A fresh directory for each run, so that a run left behind by an earlier
# one (a killed break check, say) can never share it.
mkdir -p "$(dirname "$work")" || exit 1
work=$(mktemp -d "$work.XXXXXX") || exit 1
cd "$work" || exit 1
fail=0
server=
socks=

cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null
  [ -n "$socks" ] && kill "$socks" 2>/dev/null
  wait 2>/dev/null
  cd / && rm -rf "$work"
}
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

# The two look-alikes are on this machine, which is one operator under all
# its names: each is given an operator name, as a configured list would.
A="--server $H/honest --operator first-operator"
L=http://localhost:$HTTP_PORT
TXSP=ee18add119d09dc5b01cde93367391947495b656c30c5935cbde8374aa9d944b

expect "two honest servers agree on the tip" 0 "verdict: ok .servers of 2 operators" \
  "$tool" $A --server $L/honest2 --operator second-operator tip
expect "proof of a real transaction exits 0" 0 "2 confirmation\(s\) checked" \
  "$tool" $A --server $L/honest2 --operator second-operator proof $TXA
expect "proof of an unknown transaction exits 1" 1 "unknown to the server" \
  "$tool" $A --server $L/honest2 --operator second-operator proof $TXN
expect "a server hiding a transaction: disagreement exits 1" 1 "contradict each other" \
  "$tool" $A --server $L/hider --operator second-operator tx $TXA
expect "proof against a hiding server exits 1 (review g8)" 1 "verdict: servers-disagree" \
  "$tool" $A --server $L/hider --operator second-operator proof $TXA
if printf '%s\n' "$out" | grep -q "^transaction:"; then
  echo "FAIL a failed proof still printed a transaction line"; fail=1
fi
expect "a server behind: lag exits 1 (review g7)" 1 "verdict: server-lagging" \
  "$tool" $A --server $L/behind --operator second-operator tx $TXSP
expect "fee estimates too far apart exit 1 (review g6)" 1 "verdict: servers-disagree" \
  "$tool" $A --server $L/feehigh --operator second-operator fee
expect "fee on signet uses 0.1 sat/vB" 0 "0.100 sat/vB, the fixed test-network rate" \
  "$tool" $A --server $L/honest2 --operator second-operator fee
expect "fee on signet uses 0.1 sat/vB even when estimates disagree" 1 "0.100 sat/vB, the fixed test-network rate" \
  "$tool" $A --server $L/feehigh --operator second-operator fee
expect "one server only: never 'agree'" 1 "warning: fewer than two operators" \
  "$tool" --server $H/honest tip
if printf '%s' "$out" | grep -q "operators give this answer"; then
  echo "FAIL one server only printed an agreed answer"; fail=1
fi
expect "this machine under two names is one operator" 1 "of 1 operator" \
  "$tool" --server $H/honest --server $L/honest2 tip
expect "the same server twice is refused" 2 "cannot be compared with itself" \
  "$tool" --server $H/honest --server $H/honest tip
expect "two paths on one host are refused" 2 "cannot be compared with itself" \
  "$tool" --server $H/honest --server $H/honest2 tip
expect "two paths on one host are refused, whatever the operator names" 2 "cannot be compared with itself" \
  "$tool" $A --server $H/honest2 --operator second-operator tip
expect "localhost and localhost. are one host" 2 "cannot be compared with itself" \
  "$tool" --server $L/honest --server http://localhost.:$HTTP_PORT/honest2 tip
# review A: refused when the servers are created, before anything is sent
expect "mempool.space and mempool.space. are one host" 2 "cannot be compared with itself" \
  "$tool" --server https://mempool.space/signet/api --server https://mempool.space./signet/api tip
expect "blockstream.info and blockstream.info. are one host" 2 "cannot be compared with itself" \
  "$tool" --server https://blockstream.info/signet/api --server https://blockstream.info./signet/api tip
expect "an operator name must be canonical" 2 "--operator NAME" \
  "$tool" --server $H/honest --operator First tip
expect "an operator name needs a server before it" 2 "--operator NAME" \
  "$tool" --operator first tip
expect "user information in an address is refused" 2 "not a usable server address" \
  "$tool" --server http://localhost:1@mempool.space/signet/api --server $H/honest tip
expect "plain http to a public address is refused" 2 "not a usable server address" \
  "$tool" --server http://mempool.space/signet/api --server $H/honest tip
expect "a mainnet server under --network signet is not counted" 1 "wrong-network" \
  "$tool" $A --server $L/mainnet --operator second-operator tip
: > posts.log
expect "broadcast is refused when a server is on mainnet, whatever the flag" 2 "is a mainnet server" \
  "$tool" --network signet $A --server $L/mainnet --operator second-operator \
  broadcast "$(cat "$tests/data/tx_a_hex.txt")"
if [ -s posts.log ]; then echo "FAIL a transaction was posted to a server"; cat posts.log; fail=1; fi
# privacy: a proxy comes only from --proxy, which takes socks5h alone
expect "proxy environment variables are ignored" 0 "verdict: ok" \
  env http_proxy=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 ALL_PROXY=socks5h://127.0.0.1:9 \
  NO_PROXY= no_proxy= "$tool" $A --server $L/honest2 --operator second-operator tip
expect "--proxy socks5:// is refused" 2 "takes socks5h://HOST:PORT" \
  "$tool" --proxy socks5://127.0.0.1:9050 $A --server $L/honest2 --operator second-operator tip
expect "--proxy http:// is refused" 2 "takes socks5h://HOST:PORT" \
  "$tool" --proxy http://127.0.0.1:8080 $A --server $L/honest2 --operator second-operator tip
expect "--proxy socks5h:// is accepted; this machine bypasses it" 0 "verdict: ok" \
  "$tool" --proxy socks5h://127.0.0.1:9 $A --server $L/honest2 --operator second-operator tip
# review of PR 39: the configured proxy is really used for a host off this
# machine, the name goes to the proxy (socks5h), and only "no
# authentication" is offered. The recorder refuses every connection.
python3 -I "$tests/socks_recorder.py" "$work" 2>socks.err &
socks=$!
for _ in $(seq 1 100); do [ -f socks_port ] && break; sleep 0.1; done
if [ ! -f socks_port ]; then
  echo "FAIL SOCKS recorder did not start"; cat socks.err; fail=1
else
  SP=$(cat socks_port)
  : > socks.log
  expect "a host off this machine goes through --proxy" 1 "." \
    env NO_PROXY='*' no_proxy='*' "$tool" --proxy socks5h://127.0.0.1:$SP \
    --server https://review-check.invalid/api --operator first-operator tip
  # 05 01 00: version 5, one method, "no authentication" (no GSSAPI);
  # 05 01 00 03 14 "review-check.invalid" 01bb: CONNECT by name, port 443
  name=$(printf 'review-check.invalid' | od -An -tx1 | tr -d ' \n')
  want="greeting 050100 connect 0501000314${name}01bb"
  if grep -qx "$want" socks.log; then
    echo "ok   the proxy got the name, and was offered no authentication only"
  else
    echo "FAIL proxy log (wanted: $want)"; sed 's/^/    /' socks.log; fail=1
  fi
fi
expect "broadcast --network mainnet is refused before any request" 2 "refusing to broadcast on mainnet" \
  "$tool" --network mainnet --server $H/honest broadcast "$(cat "$tests/data/tx_a_hex.txt")"
if [ -s posts.log ]; then echo "FAIL a transaction was posted to a server"; fail=1; fi

exit $fail
