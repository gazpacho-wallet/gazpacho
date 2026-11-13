#!/bin/sh
# Check a libsodium release tarball before its SHA-256 is pinned in
# ports/storage/crypto/CMakeLists.txt (spec/storage-encryption.md 13).
#
# usage: tools/verify-libsodium.sh VERSION [FOLDER]
#
# Downloads libsodium-VERSION.tar.gz and its .minisig from
# download.libsodium.org into FOLDER (default: a new temporary folder),
# verifies the minisign signature against libsodium's published key (the one
# on https://doc.libsodium.org/installation), with `minisign` if installed or
# else tools/minisign-verify.py (needs Python's `cryptography`), and prints
# the SHA-256 and the signature's trusted comment. Run it on a build machine,
# never on a personal computer.
set -eu
KEY=RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
v=$1
dir=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")" && pwd)
cd "$dir"
f=libsodium-$v.tar.gz
for x in "$f" "$f.minisig"; do
    [ -f "$x" ] || curl -fsSLO "https://download.libsodium.org/libsodium/releases/$x"
done
if command -v minisign >/dev/null 2>&1; then
    minisign -V -P "$KEY" -m "$f"
else
    python3 -I "$here/minisign-verify.py" "$KEY" "$f" "$f.minisig"
fi
sha256sum "$f"
echo "Pinned in ports/storage/crypto/CMakeLists.txt:"
grep -E 'GZ_SODIUM_(VERSION|SHA256) ' "$here/../ports/storage/crypto/CMakeLists.txt"
