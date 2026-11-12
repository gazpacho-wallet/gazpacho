#!/bin/sh
# Tests of gz-wallet-tx that need no network.  usage: test_tool.sh TOOL DIR
# The phrase is the one published in BIP 86: public, not a secret.
set -u
tool="$1"; dir="$2"
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
C1=0100000000000000000000000000000000000000000000000000000000000000:0:100000:0:0
C2=0200000000000000000000000000000000000000000000000000000000000000:1:80000:0:1
plan() { "$tool" plan --network signet --in "$P" --to-script $FACTORY --amount 150000 \
           --change-index 3 --coin $C1 --coin $C2 "$@"; }

"$tool" >/dev/null 2>&1; check usage [ $? -eq 2 ]
"$tool" plan --network mainnet --in "$P" --to-script $FACTORY --amount 150000 --change-index 3 \
  --coin $C1 >"$dir/out" 2>"$dir/err"
check mainnet-refused [ $? -eq 1 ]
check mainnet-message grep -qx 'gz-wallet-tx: refusing mainnet' "$dir/err"
check mainnet-nothing-printed [ ! -s "$dir/out" ]

plan >"$dir/plan1" 2>"$dir/err"; check plan-ok [ $? -eq 0 ]
plan >"$dir/plan2" 2>/dev/null
check plan-deterministic cmp -s "$dir/plan1" "$dir/plan2"
check plan-fee grep -qx 'fee 22' "$dir/plan1"
check plan-vsize grep -qx 'vsize 212' "$dir/plan1"
check plan-change grep -qx "change 29978 at m/86'/1'/0'/1/3" "$dir/plan1"
check plan-path-no-placeholder sh -c "! grep -q \"coin'\" '$dir/plan1'"
check plan-no-signed-without-release sh -c "! grep -q '^signed' '$dir/plan1'"
plan --release >"$dir/rel" 2>/dev/null; check release-ok [ $? -eq 0 ]
sed -n 's/^signed //p' "$dir/rel" > "$dir/hex"
check release-hex [ -s "$dir/hex" ]
"$tool" decode < "$dir/hex" > "$dir/dec"; check decode-ok [ $? -eq 0 ]
check decode-same-txid [ "$(sed -n 's/^txid //p' "$dir/dec")" = "$(sed -n 's/^txid //p' "$dir/plan1")" ]
check decode-output0 grep -qx "output 0 150000 $FACTORY" "$dir/dec"
check decode-vsize grep -qx 'vsize 212' "$dir/dec"
printf '0200' | "$tool" decode >/dev/null 2>&1; check decode-refuses-garbage [ $? -eq 1 ]
# released again: signed afresh (other signatures), the same txid
plan --release >"$dir/rel2" 2>/dev/null; check release-again-ok [ $? -eq 0 ]
check release-again-same-txid [ "$(sed -n 's/^txid //p' "$dir/rel2")" = "$(sed -n 's/^txid //p' "$dir/rel")" ]
check release-again-new-signatures sh -c "! cmp -s '$dir/rel' '$dir/rel2'"
# the funding output must be taproot
"$tool" plan --network signet --in "$P" --to-script 0014fafafafafafafafafafafafafafafafafafafa \
  --amount 150000 --change-index 3 --coin $C1 --coin $C2 >/dev/null 2>"$dir/err"
check funding-not-p2tr [ $? -eq 1 ]
check funding-not-p2tr-message grep -qx 'gz-wallet-tx: cannot build the funding: destination script not accepted' "$dir/err"
"$tool" plan --network signet --in "$P" --to-script 5220fafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafafa \
  --amount 150000 --change-index 3 --coin $C1 --coin $C2 >/dev/null 2>&1
check funding-v2-refused [ $? -eq 1 ]

plan --feerate 2000 >/dev/null 2>"$dir/err"; check rate-above-ceiling [ $? -eq 1 ]
check rate-above-ceiling-message grep -q 'fee rate above' "$dir/err"
plan --feerate server >/dev/null 2>&1; check plan-no-server-rate [ $? -eq 2 ]
plan --amount 329 --to-script $FACTORY >/dev/null 2>"$dir/err"; check dust [ $? -eq 1 ]
"$tool" plan --network signet --in "$P" --to-script $FACTORY --amount 150000 --change-index 3 \
  --coin 01:0:100000:0:0 >/dev/null 2>&1; check bad-coin [ $? -eq 1 ]
chmod 640 "$P"
plan >/dev/null 2>"$dir/err"; check phrase-perms [ $? -eq 1 ]
check phrase-perms-message grep -q 'cannot use the phrase file' "$dir/err"
chmod 600 "$P"
# one coin is enough for a smaller amount
"$tool" plan --network signet --in "$P" --to-script $FACTORY --amount 50000 --change-index 3 \
  --coin 0100000000000000000000000000000000000000000000000000000000000000:0:100000:0:0 \
  >/dev/null 2>&1; check one-coin-ok [ $? -eq 0 ]

echo "test_tool: $n checks, $fail failures"
[ $fail -eq 0 ]
