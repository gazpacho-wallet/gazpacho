#!/bin/sh
# Tests of gz-wallet-tx's chain commands against fake servers on this machine
# (127.0.0.1 only, fake_esplora.py).  usage: test_tool_chain.sh TOOL DIR
# Exit 0 pass, 1 fail, 77 skipped (no python3, or the tool was built without
# the chain port).  The phrase is the one published in BIP 86: public.
set -u
tool="$1"; dir="$2"; here=$(cd "$(dirname "$0")" && pwd)
command -v python3 >/dev/null 2>&1 || { echo "python3 not found: skipped"; exit 77; }
if "$tool" broadcast --network signet 2>&1 | grep -q 'built without the chain port'; then
  echo "built without the chain port: skipped"; exit 77
fi
rm -rf "$dir"; mkdir -p "$dir"
fail=0; n=0
check() { # check NAME CONDITION...
  name="$1"; shift; n=$((n + 1))
  if "$@"; then :; else echo "FAIL $name"; fail=$((fail + 1)); fi
}
P="$dir/phrase"
printf 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n' > "$P"
chmod 600 "$P"
FACTORY=5120fafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafa

# The wallet's coin sits at m/86'/1'/0'/1/0: learn its script from a plan
# whose change goes there (output 1 of the released transaction).
"$tool" plan --network signet --in "$P" --to-script $FACTORY --amount 50000 --change-index 0 \
  --coin 0100000000000000000000000000000000000000000000000000000000000000:0:100000:0:0 \
  --release > "$dir/seed" 2>&1 || { echo "FAIL seed plan"; cat "$dir/seed"; exit 1; }
sed -n 's/^signed //p' "$dir/seed" | "$tool" decode | sed -n 's/^output 1 [0-9]* //p' > "$dir/coin_script"
[ -s "$dir/coin_script" ] || { echo "FAIL no change script"; exit 1; }

server=
cleanup() { [ -n "$server" ] && kill "$server" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT
python3 -I "$here/fake_esplora.py" "$dir" 2>"$dir/server.err" &
server=$!
for _ in $(seq 1 100); do [ -f "$dir/port" ] && break; sleep 0.1; done
[ -f "$dir/port" ] || { echo "fake servers did not start"; cat "$dir/server.err"; exit 1; }
PORT=$(cat "$dir/port")
H=http://127.0.0.1:$PORT L=http://localhost:$PORT
# the two names are one machine: each is given its own operator name
two() { echo "--server $H/$1 --operator op-one --server $L/$2 --operator op-two"; }
fund() { # fund PERSONA1 PERSONA2 more...
  s1=$1 s2=$2; shift 2
  "$tool" fund --network signet --in "$P" --to-script $FACTORY --amount 50000 \
    --change-index 3 --scan 2 --pace 0 --retry-pause 20 $(two $s1 $s2) "$@"
}

# --- 1. one operator failing for a while, then answering: asked again
fund good flaky > "$dir/o1" 2> "$dir/e1"
check retry-recovers [ $? -eq 0 ]
check retry-found-coin grep -qx 'confirmed coins found 1' "$dir/o1"
check retry-said-so grep -q "lookup of receive index 0 (m/86'/1'/0'/0/0): no-quorum; asking again in 20 ms (try 2 of 5)" "$dir/e1"
check retry-names-server grep -q 'server 2 (op-two): unreachable' "$dir/e1"
check retry-no-signed sh -c "! grep -q '^signed' '$dir/o1'"

# --- 2. an operator that never recovers: the error names index, kind, server
fund good down > "$dir/o2" 2> "$dir/e2"
check down-fails [ $? -eq 1 ]
check down-names-index grep -q "coin lookup failed at receive index 0 (m/86'/1'/0'/0/0): no-quorum" "$dir/e2"
check down-names-server grep -q 'server 2 (op-two): unreachable' "$dir/e2"
check down-bounded [ "$(grep -c 'asking again' "$dir/e2")" -eq 4 ]
# the same to one file: the standard output line comes before the error
fund good down > "$dir/both" 2>&1
check order-feerate-first [ "$(sed -n 1p "$dir/both")" = "feerate 100 sat/kvB, ceiling 1000" ]

# --- 3. the printed change path names the real coin type
fund good good2 > "$dir/o3" 2> "$dir/e3"
check fund-ok [ $? -eq 0 ]
check fund-change-path grep -qx "change 49984 at m/86'/1'/0'/1/3" "$dir/o3"
check fund-no-placeholder sh -c "! grep -q \"coin'\" '$dir/o3'"
TXID=$(sed -n 's/^txid //p' "$dir/o3")
check fund-txid [ ${#TXID} -eq 64 ]

# --- 4. the txid guard
: > "$dir/posts.log"
WRONG=0000000000000000000000000000000000000000000000000000000000000001
fund good good2 --expect-txid $WRONG --broadcast > "$dir/o4" 2> "$dir/e4"
check guard-refuses [ $? -eq 1 ]
check guard-message grep -q "the built txid is not --expect-txid $WRONG; nothing signed or sent" "$dir/e4"
check guard-nothing-signed sh -c "! grep -q '^signed' '$dir/o4'"
check guard-nothing-posted [ ! -s "$dir/posts.log" ]

# --- 5. guarded broadcast, every server's answer printed
fund good good2 --expect-txid "$TXID" --broadcast > "$dir/o5" 2> "$dir/e5"
check guarded-broadcast-ok [ $? -eq 0 ]
check per-server-1-accepted grep -qx 'server 1 (op-one): accepted' "$dir/o5"
check per-server-2-accepted grep -qx 'server 2 (op-two): accepted' "$dir/o5"
check broadcast-ok-line grep -qx 'broadcast ok' "$dir/o5"
check posted-both [ "$(grep -c " $TXID\$" "$dir/posts.log")" -eq 2 ]
sed -n 's/^signed //p' "$dir/o5" > "$dir/signed.hex"

# --- 6. one refusing, one already having it
fund refuse known --broadcast > "$dir/o6" 2> "$dir/e6"
check mixed-ok [ $? -eq 0 ]
check refused-with-words grep -q '^server 1 (op-one): refused (HTTP 400): .*bad-txns-inputs-missingorspent' "$dir/o6"
check already-had-it grep -qx 'server 2 (op-two): already had it' "$dir/o6"
fund refuse refuse --broadcast > "$dir/o7" 2> "$dir/e7"
check all-refuse-fails [ $? -eq 1 ]
check all-refuse-message grep -q 'broadcast failed: no server accepted it' "$dir/e7"
check all-refuse-listed [ "$(grep -c 'refused (HTTP 400)' "$dir/o7")" -eq 2 ]

# --- 7. broadcast --hex: exactly the reviewed bytes
# the change is at index 3: scan 4 indexes of each chain
bc() { "$tool" broadcast --network signet --hex "$dir/signed.hex" --scan 4 --pace 0 "$@"; }
: > "$dir/posts.log"
bc --in "$P" --to-script $FACTORY --expect-txid "$TXID" $(two good good2) > "$dir/o8" 2> "$dir/e8"
check hex-ok [ $? -eq 0 ]
check hex-txid grep -qx "txid $TXID" "$dir/o8"
check hex-dest grep -qx 'output 0 50000 to the stated destination' "$dir/o8"
check hex-change grep -qx "output 1 49984 to this wallet at m/86'/1'/0'/1/3" "$dir/o8"
check hex-per-server [ "$(grep -c ': accepted$' "$dir/o8")" -eq 2 ]
check hex-posted-same [ "$(grep -c " $TXID\$" "$dir/posts.log")" -eq 2 ]
check hex-input-wallet grep -qx "input 0 100000 from this wallet at m/86'/1'/0'/1/0" "$dir/o8"
check hex-fee grep -qx 'fee 16' "$dir/o8"
check hex-feerate grep -qx 'feerate 103 sat/kvB, ceiling 1000' "$dir/o8"
: > "$dir/posts.log"
# a fee far above the ceiling: the same coin, signed with a burning rate
COIN=$(cat "$dir/coin_txid")
"$tool" plan --network signet --in "$P" --to-script $FACTORY --amount 50000 --change-index 3 \
  --coin "$COIN:0:100000:1:0" --feerate 60000 --max-feerate 100000 --release > "$dir/burn" 2>&1
sed -n 's/^signed //p' "$dir/burn" > "$dir/burn.hex"
check burn-built [ -s "$dir/burn.hex" ]
"$tool" broadcast --network signet --hex "$dir/burn.hex" --in "$P" --scan 4 --pace 0 \
  --to-script $FACTORY $(two good good2) > "$dir/o13" 2> "$dir/e13"
check burn-refused [ $? -eq 1 ]
check burn-message grep -q 'is above the ceiling .*nothing sent' "$dir/e13"
check burn-not-posted [ ! -s "$dir/posts.log" ]
# a ceiling raised on purpose lets it through the check (posted to fakes only)
"$tool" broadcast --network signet --hex "$dir/burn.hex" --in "$P" --scan 4 --pace 0 \
  --to-script $FACTORY --max-feerate 100000 $(two good good2) > /dev/null 2>&1
check burn-raised-ceiling-sent [ $? -eq 0 ]
: > "$dir/posts.log"
# an input whose coin the servers do not know
sed -n 's/^signed //p' "$dir/seed" > "$dir/unknown.hex"
"$tool" broadcast --network signet --hex "$dir/unknown.hex" --in "$P" --scan 4 --pace 0 \
  --to-script $FACTORY $(two good good2) > /dev/null 2> "$dir/e14"
check unknown-input-refused [ $? -eq 1 ]
check unknown-input-message grep -q 'the coin spent by input 0 is not known to the servers' "$dir/e14"
check unknown-not-posted [ ! -s "$dir/posts.log" ]
bc --in "$P" $(two good good2) > "$dir/o9" 2> "$dir/e9"
check hex-unknown-output-refused [ $? -eq 1 ]
check hex-unknown-output-message grep -q 'output 0 pays neither this wallet' "$dir/e9"
bc --in "$P" --to-script $FACTORY --expect-txid $WRONG $(two good good2) > /dev/null 2> "$dir/e10"
check hex-guard-refuses [ $? -eq 1 ]
check hex-guard-message grep -q 'the txid is not --expect-txid' "$dir/e10"
# change outside the scanned range is not this wallet's as far as the tool knows
"$tool" broadcast --network signet --hex "$dir/signed.hex" --scan 3 --pace 0 \
  --to-script $FACTORY $(two good good2) > /dev/null 2> "$dir/e11"
check hex-dest-only-refuses-change [ $? -eq 1 ]
sed -n 's/^signed //p' "$dir/seed" | head -c 40 > "$dir/cut.hex"
"$tool" broadcast --network signet --hex "$dir/cut.hex" --to-script $FACTORY $(two good good2) \
  > /dev/null 2>&1
check hex-garbage-refused [ $? -eq 1 ]
check hex-nothing-posted [ ! -s "$dir/posts.log" ]
bc --in "$P" --to-script $FACTORY --server $H/good > /dev/null 2> "$dir/e12"
check one-server-refused [ $? -eq 1 ]
check one-server-message grep -q 'give --server at least twice' "$dir/e12"
check still-nothing-posted [ ! -s "$dir/posts.log" ]

echo "test_tool_chain: $n checks, $fail failures"
[ $fail -eq 0 ]
