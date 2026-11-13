#!/bin/sh
# Prepare N worker copies of this checkout and run the rule-removed runs and
# the mutants of the signing engine through tools/signing-mutants.py.
# usage: tools/signing-mutants-run.sh WORKDIR N SECP_SOURCE_DIR [rules|mutants|both|again]
# "again": the rules, then only the survivors of WORKDIR/mutants.log, against the tests as they are now.
# Each worker is WORKDIR/wI/src (a copy, without build directories) and
# WORKDIR/wI/build. Results go to WORKDIR/rules.log and WORKDIR/mutants.log.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
work=$1; n=$2; secp=$3; what=${4:-both}
mkdir -p "$work"
builds=""
i=1
while [ "$i" -le "$n" ]; do
    w="$work/w$i"
    mkdir -p "$w/src"
    tar -C "$here" --exclude='./build*' --exclude=./.git -cf - . | tar -C "$w/src" -xf -
    if [ ! -f "$w/build/CMakeCache.txt" ]; then
        cmake -S "$w/src" -B "$w/build" -DFETCHCONTENT_SOURCE_DIR_SECP256K1-ZKP="$secp" > "$w/cmake.log" 2>&1
    fi
    cmake --build "$w/build" --target test_signing -j2 > "$w/build.log" 2>&1
    builds="$builds $w/build"
    i=$((i + 1))
done
if [ "$what" = rules ] || [ "$what" = both ] || [ "$what" = again ]; then python3 "$here/tools/signing-mutants.py" rules "$here" $builds > "$work/rules.log" 2>&1; fi
if [ "$what" = again ]; then
    grep '^SURVIVOR ' "$work/mutants.log" | sed 's/^SURVIVOR //' > "$work/survivors.txt"
    python3 "$here/tools/signing-mutants.py" mutants "$here" $builds --names "$work/survivors.txt" > "$work/mutants-again.log" 2>&1
elif [ "$what" != rules ]; then python3 "$here/tools/signing-mutants.py" mutants "$here" $builds > "$work/mutants.log" 2>&1; fi
echo finished > "$work/done"
