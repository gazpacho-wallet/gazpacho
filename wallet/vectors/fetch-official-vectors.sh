#!/bin/sh
# Fetch the official test-vector files at fixed commits into DIR, for
# gen-official-vectors.py.  usage: fetch-official-vectors.sh DIR
set -eu
dir="$1"
BIPS=b34d9f751791d4feb22feff4f2ed00bcac83961b      # github.com/bitcoin/bips
MNEMONIC=b57a5ad77a981e743f4167ab2f7927a55c1e82a8  # github.com/trezor/python-mnemonic
mkdir -p "$dir"
for f in bip-0032.mediawiki bip-0086.mediawiki bip-0350.mediawiki bip-0341/wallet-test-vectors.json; do
  curl -sfL -o "$dir/$(basename "$f")" "https://raw.githubusercontent.com/bitcoin/bips/$BIPS/$f"
done
# BIP 39's "Test vectors" section points to this file.
curl -sfL -o "$dir/bip39-vectors.json" "https://raw.githubusercontent.com/trezor/python-mnemonic/$MNEMONIC/vectors.json"
printf 'bips %s\npython-mnemonic %s\n' "$BIPS" "$MNEMONIC" > "$dir/SOURCES"
