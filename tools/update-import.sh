#!/usr/bin/env bash
# tools/update-import.sh <superscalar-checkout> <commit-ish>
#
# Re-copies the imported SuperScalar file set (byte-for-byte, via `git show`) from a
# SuperScalar checkout at the given commit, regenerates core/superscalar/IMPORT.md and
# LICENSE, checks the secp256k1-zkp pin, then builds and runs the reference test.
# Exits non-zero if anything fails, including the reference test.
# The checkout is only read (git show / rev-parse); it is never modified.
#
# Re-running with the already-pinned commit is a no-op (IMPORT.md keeps its "Imported on"
# date when the commit is unchanged).
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 <superscalar-checkout> <commit-ish>" >&2; exit 2; }
REPO=$1
COMMIT=$(git -C "$REPO" rev-parse --verify "$2^{commit}")
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST=$ROOT/core/superscalar
UPSTREAM_URL=https://github.com/8144225309/SuperScalar

# The 17 imported translation units (fee_estimator_static.c satisfies fee_estimator_static_init).
C_FILES="factory musig dw_state ladder tx_builder tapscript adaptor shachain util hd_key bip39 bech32m crypto_aead fee htlc_fee_bump bolt11 fee_estimator_static"

show() { git -C "$REPO" show "$COMMIT:$1"; }

# ---- header closure (quoted includes only; <...> includes are system/secp256k1) ----
declare -A SEEN=()
FILES=()
queue=()
for f in $C_FILES; do queue+=("src/$f.c"); done
while [ ${#queue[@]} -gt 0 ]; do
  p=${queue[0]}; queue=("${queue[@]:1}")
  [ -n "${SEEN[$p]:-}" ] && continue
  SEEN[$p]=1; FILES+=("$p")
  while IFS= read -r inc; do
    case "$inc" in
      superscalar/*) cand="include/$inc" ;;
      *)             cand="$(dirname "$p")/$inc" ;;
    esac
    git -C "$REPO" cat-file -e "$COMMIT:$cand" 2>/dev/null \
      || { echo "cannot resolve #include \"$inc\" from $p at $COMMIT" >&2; exit 1; }
    queue+=("$cand")
  done < <(show "$p" | sed -n 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*"\([^"]*\)".*/\1/p')
done
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | sort)

# ---- secp256k1-zkp pin must match ----
UP_TAG=$(show CMakeLists.txt | sed -n 's/^[[:space:]]*GIT_TAG[[:space:]]*\([0-9a-f]\{40\}\).*/\1/p' | head -1)
OUR_TAG=$(sed -n 's/^[[:space:]]*GIT_TAG[[:space:]]*\([0-9a-f]\{40\}\).*/\1/p' "$ROOT/CMakeLists.txt" | head -1)
[ -n "$UP_TAG" ] && [ "$UP_TAG" = "$OUR_TAG" ] \
  || { echo "secp256k1-zkp pin differs: upstream '$UP_TAG' vs ours '$OUR_TAG'; update CMakeLists.txt deliberately" >&2; exit 1; }

# ---- copy ----
OLD_DATE=""
if [ -f "$DEST/IMPORT.md" ] && grep -q "^Pinned commit: $COMMIT\$" "$DEST/IMPORT.md"; then
  OLD_DATE=$(sed -n 's/^Imported on: //p' "$DEST/IMPORT.md")
fi
rm -rf "$DEST/src" "$DEST/include"
for p in "${FILES[@]}"; do
  case "$p" in
    src/*)     out="$DEST/$p" ;;
    include/*) out="$DEST/$p" ;;
    *) echo "unexpected path $p" >&2; exit 1 ;;
  esac
  mkdir -p "$(dirname "$out")"
  show "$p" > "$out"
done
show LICENSE > "$DEST/LICENSE"

COMMIT_DATE=$(git -C "$REPO" show -s --format=%cI "$COMMIT")
SUBJECT=$(git -C "$REPO" show -s --format=%s "$COMMIT")
IMPORT_DATE=${OLD_DATE:-$(date -u +%Y-%m-%d)}
{
  echo "# Imported SuperScalar files"
  echo
  echo "These files are copied byte-for-byte from SuperScalar (MIT licence, see LICENSE in this directory)."
  echo "Do not edit them. Re-import with tools/update-import.sh. Workarounds go in core/shim/."
  echo
  echo "Upstream: $UPSTREAM_URL"
  echo "Pinned commit: $COMMIT"
  echo "Commit date: $COMMIT_DATE"
  echo "Commit subject: $SUBJECT"
  echo "Imported on: $IMPORT_DATE"
  echo "secp256k1-zkp pin (from upstream CMakeLists.txt, mirrored in ../../CMakeLists.txt): $UP_TAG"
  echo
  echo "| Local path (relative to core/superscalar) | Upstream path | SHA-256 |"
  echo "|---|---|---|"
  for p in "${FILES[@]}"; do
    echo "| $p | $p | $(sha256sum "$DEST/$p" | cut -d' ' -f1) |"
  done
  echo "| LICENSE | LICENSE | $(sha256sum "$DEST/LICENSE" | cut -d' ' -f1) |"
} > "$DEST/IMPORT.md"

# verify identity against git object content
for p in "${FILES[@]}" LICENSE; do
  a=$(show "$p" | sha256sum | cut -d' ' -f1); b=$(sha256sum "$DEST/$p" | cut -d' ' -f1)
  [ "$a" = "$b" ] || { echo "byte-identity check failed for $p" >&2; exit 1; }
done
echo "imported ${#FILES[@]} files + LICENSE from $COMMIT"

# ---- reference test ----
BUILD=${GZ_UPDATE_BUILD_DIR:-$ROOT/build-update}
cmake -S "$ROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$BUILD" -j"$(nproc)" >/dev/null
ctest --test-dir "$BUILD" --output-on-failure
echo "update-import: OK ($COMMIT)"
