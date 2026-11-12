#!/bin/sh
# Run every libFuzzer target in a build directory for a fixed time each.
#
# usage: tools/run-fuzz.sh BUILD_DIR [SECONDS]      (default 60 seconds)
#
# A fuzz target is an executable named fuzz_<name> built with
# -DGZ_LIBFUZZER=ON (see docs/notes/ci.md). If fuzz/corpus/<name>/ exists in
# the repository, a scratch copy of it is the starting corpus; the
# repository's copy is never written. Exits 1 if any target finds a crash,
# a leak, an undefined-behaviour report or a timeout; libFuzzer prints the
# failing input (as bytes and Base64) in the log.
set -eu
build=$1
secs=${2:-60}
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

targets=$(find "$build" -type f -perm -u+x -name 'fuzz_*' | sort)
if [ -z "$targets" ]; then
    echo "FAIL: no fuzz_* executables in $build, but the sources define LLVMFuzzerTestOneInput."
    echo "Fuzz targets must be built as fuzz_<name> when GZ_LIBFUZZER=ON (docs/notes/ci.md)."
    exit 1
fi

fail=0
for t in $targets; do
    name=$(basename "$t" | sed 's/^fuzz_//')
    corpus=$work/$name
    mkdir -p "$corpus"
    if [ -d "$root/fuzz/corpus/$name" ]; then
        cp -R "$root/fuzz/corpus/$name/." "$corpus/"
    fi
    echo "=== fuzz_$name for ${secs}s"
    if ! (cd "$work" && "$t" -max_total_time="$secs" -timeout=10 -rss_limit_mb=2048 \
              -print_final_stats=1 "$corpus"); then
        echo "FAILED: fuzz_$name"
        fail=1
    fi
done
[ "$fail" -eq 0 ] || { echo "FAIL: a fuzz target failed"; exit 1; }
echo "PASS: every fuzz target ran ${secs}s without a finding"
