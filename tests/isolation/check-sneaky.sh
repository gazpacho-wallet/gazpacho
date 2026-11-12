#!/bin/sh
# The isolation check must itself be checked: it has to refuse objects that do
# what the core must never do, and name every problem.
#
# usage: check-sneaky.sh CHECKER SNEAKY_OBJECT C_COMPILER SOURCE_DIR WORK_DIR CORE_FLAGS
# SOURCE_DIR is tests/isolation; CORE_FLAGS is the one string of flags the
# core library is compiled with.
set -u
checker="$1"; object="$2"; cc="$3"; dir="$4"; work="$5"; flags="$6"
failed=0
x86=0; [ "$(uname -m)" = "x86_64" ] && x86=1

# Does the check, run on $1, print a FOUND line matching $2?
refuses() {
    out=$(sh "$checker" "$1" 2>&1) && { echo "FAIL: the isolation check passed $1"; failed=1; return; }
    if printf '%s\n' "$out" | grep -Eq "^FOUND $2"; then echo "ok: refused for: $2"
    else echo "FAIL: $1 not refused for: $2"; printf '%s\n' "$out"; failed=1; fi
}

echo "-- an object that does several forbidden things"
refuses "$object" "outside symbol: time\$"
refuses "$object" "weak symbol: getenv\$"
refuses "$object" "writable data: sneaky_counter\$"
refuses "$object" "writable data: sneaky_table\$"
if [ "$x86" -eq 1 ]; then
    refuses "$object" "instruction: syscall\$"
    refuses "$object" "instruction: rdtsc\$"
fi

echo "-- one forbidden thing at a time, each built with the core's flags: $flags"
build_case() { "$cc" $flags -DCASE="$1" -c "$dir/cases.c" -o "$work/case-$1.o" 2>"$work/case-$1.err"; }
expect_case() {
    if build_case "$1"; then refuses "$work/case-$1.o" "$2"
    else echo "FAIL: case $1 did not compile"; cat "$work/case-$1.err"; failed=1; fi
}
if [ "$x86" -eq 1 ]; then
    expect_case 1 "instruction: syscall\$"
    expect_case 2 "instruction: syscall\$"
    expect_case 3 "instruction: int\$"
    expect_case 4 "instruction: cpuid\$"
    expect_case 5 "instruction: rdpmc\$"
    expect_case 6 "instruction: xgetbv\$"
    expect_case 7 "instruction: rdrand\$"
    expect_case 8 "instruction: call to a fixed address\$"
    expect_case 9 "instruction: segment register access\$"
    expect_case 10 "writable section: .data "
    expect_case 11 "writable section: .data "
fi
expect_case 12 "writable section: mystate "
expect_case 13 "writable (data|section): "
expect_case 14 "writable section: .tbss "

echo "-- inline assembly in a source file"
out=$(sh "$checker" "$object" --sources "$dir/cases.c" 2>&1)
if printf '%s\n' "$out" | grep -q "^FOUND inline assembly: .*cases.c:"; then echo "ok: refused for: inline assembly"
else echo "FAIL: inline assembly in a source file not reported"; failed=1; fi

echo "-- refused by the compiler"
if [ "$x86" -eq 1 ]; then
    if build_case 15; then echo "FAIL: the core's flags accept floating point"; failed=1
    else echo "ok: the core's flags reject floating point"; fi
fi
# A variable-length array must be rejected, and the same file must compile
# once -Wvla is taken out of the flags (so it is rejected for that reason).
without=$(printf '%s' "$flags" | sed 's/-Wvla//')
if "$cc" $without -c "$dir/vla.c" -o "$work/vla-control.o" 2>/dev/null; then echo "ok: the VLA file compiles without -Wvla"
else echo "FAIL: the VLA file does not compile even without -Wvla"; failed=1; fi
if "$cc" $flags -c "$dir/vla.c" -o "$work/vla.o" 2>/dev/null; then echo "FAIL: the core's flags did not reject a variable-length array"; failed=1
else echo "ok: the core's flags reject a variable-length array"; fi

echo "-- known not to be caught (listed in the check's own header)"
if [ "$x86" -eq 1 ]; then
    for n in 20 21 22; do
        if build_case "$n" && sh "$checker" "$work/case-$n.o" >/dev/null 2>&1; then echo "as documented: case $n passes"
        else echo "FAIL: case $n is now refused or does not build: update the list in the check"; failed=1; fi
    done
fi

[ "$failed" -eq 0 ] && echo "PASS: the isolation check refuses every case it should"
exit "$failed"
