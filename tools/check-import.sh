#!/bin/sh
# Check core/superscalar/ byte for byte against the SHA-256 sums in
# core/superscalar/IMPORT.md.
#
# Fails if any listed file is missing or differs from its recorded sum, if
# any file under core/superscalar/ (other than IMPORT.md) is not listed, or if
# the table cannot be read. So an edit to an imported file, a stray file, or a
# deleted one cannot pass unnoticed. A deliberate re-import goes through
# tools/update-import.sh, which rewrites the table.
#
# usage: tools/check-import.sh            (from anywhere in the repository)
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
dir=$root/core/superscalar
table=$dir/IMPORT.md
[ -f "$table" ] || { echo "FAIL: $table not found"; exit 1; }

sums=$(mktemp)
trap 'rm -f "$sums"' EXIT

# Rows look like: | local/path | upstream/path | <64 hex> |
awk -F'|' 'NF >= 5 {
    p = $2; h = $4
    gsub(/^[ \t]+|[ \t]+$/, "", p); gsub(/^[ \t]+|[ \t]+$/, "", h)
    if (h ~ /^[0-9a-f]{64}$/) print h "  " p
}' "$table" > "$sums"

listed=$(wc -l < "$sums" | tr -d ' ')
[ "$listed" -gt 0 ] || { echo "FAIL: no SHA-256 rows found in $table"; exit 1; }

fail=0
if ! (cd "$dir" && sha256sum --check --strict --quiet "$sums"); then
    fail=1
fi

# Every file present must be listed (IMPORT.md itself excepted).
present=$(cd "$dir" && find . -type f ! -name IMPORT.md | sed 's|^\./||' | sort)
known=$(awk '{ print $2 }' "$sums" | sort)
extra=$(printf '%s\n' "$present" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    printf '%s\n' "$known" | grep -qxF "$f" || printf '%s\n' "$f"
done)
if [ -n "$extra" ]; then
    printf 'FOUND unlisted file: %s\n' $extra
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: core/superscalar/ does not match core/superscalar/IMPORT.md"
    echo "Imported files are never edited (CONTRIBUTING.md); re-import with tools/update-import.sh."
    exit 1
fi
echo "PASS: $listed files in core/superscalar/ match the SHA-256 sums in IMPORT.md"
