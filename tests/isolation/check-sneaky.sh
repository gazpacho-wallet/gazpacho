#!/bin/sh
# The isolation check must itself be checked: it has to refuse objects and
# sources that do what the core must never do, let honest ones through, and
# not compile the ones the compiler is relied on to reject.
#
# usage: check-sneaky.sh CHECKER SNEAKY_OBJECT C_COMPILER SOURCE_DIR WORK_DIR CORE_FLAGS
set -u
checker="$1"; object="$2"; cc="$3"; dir="$4"; work="$5"; flags="$6"
failed=0
x86=0; [ "$(uname -m)" = "x86_64" ] && x86=1

fail() { echo "FAIL: $1"; failed=1; }
build_case() { "$cc" $flags -I"$dir" -DCASE="$1" -c "$dir/cases.c" -o "$work/case-$1.o" 2>"$work/case-$1.err"; }

# The check, run on the object of case $1 (plus cases.c as a source), must
# print a FOUND line matching $2.
refuses_object() {
    build_case "$1" || { fail "case $1 did not compile"; cat "$work/case-$1.err"; return; }
    out=$(sh "$checker" "$work/case-$1.o" --sources "$cc" "$flags -I$dir -DCASE=$1" "$dir/cases.c" 2>&1) &&
        { fail "case $1 was not refused"; return; }
    printf '%s\n' "$out" | grep -Eq "^FOUND $2" && echo "ok: case $1 refused for: $2" ||
        { fail "case $1 not refused for: $2"; printf '%s\n' "$out"; }
}

echo "-- an object that does several forbidden things at once"
build_asan=1
refuses_object_simple() {
    out=$(sh "$checker" "$object" 2>&1) && { fail "the sneaky object was not refused"; return; }
    printf '%s\n' "$out" | grep -Eq "^FOUND $1" && echo "ok: refused for: $1" || fail "not refused for: $1"
}
refuses_object_simple "outside symbol: time\$"
refuses_object_simple "weak symbol: getenv\$"
refuses_object_simple "writable data: sneaky_counter\$"
refuses_object_simple "writable data: sneaky_table\$"
if [ "$x86" -eq 1 ]; then
    refuses_object_simple "instruction: syscall\$"
    refuses_object_simple "instruction: rdtsc\$"
fi

echo "-- one forbidden thing at a time, built with the core's flags: $flags"
if [ "$x86" -eq 1 ]; then
    refuses_object 1 "instruction: syscall\$"
    refuses_object 2 "instruction: syscall\$"
    refuses_object 3 "instruction: int\$"
    refuses_object 4 "instruction: sysenter\$"
    refuses_object 5 "instruction: cpuid\$"
    refuses_object 6 "instruction: rdpmc\$"
    refuses_object 7 "instruction: xgetbv\$"
    refuses_object 8 "instruction: rdrand\$"
    refuses_object 9 "instruction: rdrand\$"
    refuses_object 10 "instruction: rdpid\$"
    refuses_object 11 "instruction: rdfsbase\$"
    refuses_object 12 "instruction: stmxcsr\$"
    refuses_object 13 "instruction: rdsspq\$"
    refuses_object 14 "instruction: xbegin\$"
    refuses_object 15 "instruction: rdtsc\$"
    refuses_object 16 "instruction: sgdt\$"
    refuses_object 17 "instruction: lsl\$"
    refuses_object 18 "instruction: segment register access\$"
    refuses_object 19 "writable section: .data "
    refuses_object 32 "instruction: rdseed\$"
    refuses_object 33 "instruction: rdtscp\$"
    refuses_object 34 "instruction: segment register access\$"
    refuses_object 35 "instruction: call or jump to a fixed address\$"
fi
refuses_object 20 "writable section: mystate "
refuses_object 21 "writable (data|section): "
refuses_object 22 "writable section: .tbss "
refuses_object 23 "init/fini array: .init_array"
refuses_object 24 "writable data: __asan_sneaky\$"
refuses_object 25 "outside symbol: __sanitizer_now\$"
refuses_object 26 "outside symbol: __stpcpy_chk\$"
refuses_object 27 "outside symbol: memfrob\$"
refuses_object 28 "ifunc: f\$"
refuses_object 30 "inline assembly: "
refuses_object 31 "inline assembly: "

echo "-- a source the scan cannot preprocess is refused, not passed unread"
build_case 50 && {
    out=$(sh "$checker" "$work/case-50.o" --sources "$work/no-such-compiler" "$flags" "$dir/cases.c" 2>&1) &&
        fail "a source that could not be preprocessed was passed" ||
        { printf '%s
' "$out" | grep -q "^FOUND source scan" && echo "ok: an unreadable source is refused" ||
          { fail "refused, but not for the source scan"; printf '%s
' "$out"; }; }
}

echo "-- a sanitized build exempts the checkers' own names, but not ordinary ones"
out=$(sh "$checker" --sanitized "$object" 2>&1) && fail "the sneaky object passed --sanitized" ||
    { printf '%s\n' "$out" | grep -q "^FOUND weak symbol: getenv$" && echo "ok: a weak getenv is still refused under --sanitized" ||
      fail "a weak getenv is not refused under --sanitized"; }
build_case 24 && {
    sh "$checker" --sanitized "$work/case-24.o" >/dev/null 2>&1 && echo "ok: case 24 (checker name) passes --sanitized" ||
        fail "case 24 refused even under --sanitized"
}
if [ "$x86" -eq 1 ]; then   # thread-local state of its own is still caught under --sanitized
    build_case 22 && {
        out=$(sh "$checker" --sanitized "$work/case-22.o" 2>&1) && fail "case 22 (thread-local) passed --sanitized" ||
            { printf '%s\n' "$out" | grep -q "^FOUND thread-local reference: " &&
              echo "ok: case 22 (thread-local) refused under --sanitized for its thread-local reference" ||
              { fail "case 22 refused under --sanitized, but not for its thread-local reference"; printf '%s\n' "$out"; }; }
    }
    build_case 18 && {
        sh "$checker" --sanitized "$work/case-18.o" >/dev/null 2>&1 &&
            echo "note: case 18 (%gs read) passes --sanitized, as the segment-register test is replaced there" ||
            echo "note: case 18 refused under --sanitized"
    }
fi
build_case 19 && {   # real writable data is still caught: symbol test runs under --sanitized
    sh "$checker" --sanitized "$work/case-19.o" >/dev/null 2>&1 &&
        echo "note: case 19 (nameless .data) passes --sanitized, as the section test is off there" ||
        echo "note: case 19 refused under --sanitized"
}

echo "-- honest objects pass"
for n in 50 51; do
    build_case "$n" || { fail "case $n did not compile"; continue; }
    sh "$checker" "$work/case-$n.o" >/dev/null 2>&1 && echo "ok: case $n (honest table) passes" ||
        { fail "case $n (honest table) refused"; sh "$checker" "$work/case-$n.o" 2>&1 | grep '^FOUND'; }
done

echo "-- floating point: refused by the compiler, or on x86 by the check where the compiler accepts it"
if ! build_case 40 2>/dev/null; then echo "ok: case 40 rejected by the compiler"
elif [ "$x86" -eq 1 ]; then refuses_object 40 "(instruction: floating-point or vector register|outside symbol: .*)\$"
else fail "case 40 compiled; the compiler was relied on to reject it"; fi
if [ "$x86" -eq 1 ]; then   # the same source without -mgeneral-regs-only: the check alone must refuse it
    without_gro=$(printf '%s' "$flags" | sed 's/-mgeneral-regs-only//')
    if "$cc" $without_gro -I"$dir" -DCASE=40 -c "$dir/cases.c" -o "$work/case-40-fp.o" 2>/dev/null; then
        out=$(sh "$checker" "$work/case-40-fp.o" 2>&1) && fail "floating-point code passed the check" ||
            { printf '%s\n' "$out" | grep -q "^FOUND instruction: floating-point or vector register$" &&
              echo "ok: floating-point code refused by the check" ||
              { fail "floating-point code refused, but not for its registers"; printf '%s\n' "$out"; }; }
    else fail "case 40 does not compile even without -mgeneral-regs-only"; fi
fi
# A variable-length array must be rejected, and the same file must compile once
# -Wvla is taken out of the flags (so it is rejected for that reason).
without=$(printf '%s' "$flags" | sed 's/-Wvla//')
"$cc" $without -c "$dir/vla.c" -o "$work/vla-control.o" 2>/dev/null &&
    echo "ok: the VLA file compiles without -Wvla" || fail "the VLA file does not compile even without -Wvla"
"$cc" $flags -c "$dir/vla.c" -o "$work/vla.o" 2>/dev/null &&
    fail "the core's flags did not reject a variable-length array" || echo "ok: the core's flags reject a variable-length array"

echo "-- known not to be caught (listed in the check's own header)"
if [ "$x86" -eq 1 ]; then
    for n in 60 61 62 63 64; do
        if build_case "$n" 2>/dev/null && sh "$checker" "$work/case-$n.o" >/dev/null 2>&1; then echo "as documented: case $n passes the check"
        elif build_case "$n" 2>/dev/null; then fail "case $n is now refused: it can be moved out of the not-caught list"
        else echo "as documented: case $n does not compile"; fi
    done
fi

[ "$failed" -eq 0 ] && echo "PASS: the isolation check behaves as its documentation says for every case"
exit "$failed"
