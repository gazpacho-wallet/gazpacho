#!/bin/sh
# Fetch the official BIP 341 and BIP 86 vector files at a fixed commit of
# github.com/bitcoin/bips into DIR and check their SHA-256, for
# gen-tx-vectors.py.  usage: fetch-tx-vectors.sh DIR
set -eu
dir="$1"
BIPS=b34d9f751791d4feb22feff4f2ed00bcac83961b   # the commit wallet/vectors uses too
mkdir -p "$dir"
for f in bip-0341/wallet-test-vectors.json bip-0086.mediawiki; do
  curl -sfL -o "$dir/$(basename "$f")" "https://raw.githubusercontent.com/bitcoin/bips/$BIPS/$f"
done
cd "$dir"
sha256sum -c <<EOF
403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f  wallet-test-vectors.json
d8d01dee331da07c2562615bc1f064c1868ec3fce61184973da76d1196c7f5b0  bip-0086.mediawiki
EOF
