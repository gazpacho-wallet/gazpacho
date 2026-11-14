#!/bin/sh
# The vendored llhttp files are byte for byte the pinned release
# (ports/api/third_party/llhttp/IMPORT.md): every file listed in SHA256SUMS
# matches, and no other file is in the folder.
#
#   tools/check-llhttp.sh ports/api/third_party/llhttp
set -eu
cd "$1"
sha256sum --check --strict --quiet SHA256SUMS
listed=$(awk '{print $2}' SHA256SUMS | sed "s|^\*||" | sort)
present=$(find . -type f ! -name SHA256SUMS ! -name IMPORT.md | sed "s|^\./||" | sort)
if [ "$listed" != "$present" ]; then
    echo "FAIL: files in third_party/llhttp differ from SHA256SUMS"
    exit 1
fi
echo "PASS: llhttp matches its pins"
