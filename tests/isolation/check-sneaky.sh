#!/bin/sh
# The isolation check must itself be checked: it has to refuse an object that
# does what the core must never do, and name every problem.
#
# usage: check-sneaky.sh CHECKER SNEAKY_OBJECT C_COMPILER VLA_SOURCE WORK_DIR CORE_FLAGS
# CORE_FLAGS is the one string of flags the core library is compiled with.
set -u
checker="$1"; object="$2"; cc="$3"; vla="$4"; work="$5"; flags="$6"
failed=0

out=$(sh "$checker" "$object" 2>&1) && { echo "FAIL: the isolation check passed the sneaky object"; failed=1; }
echo "$out"

expect() {
    if printf '%s\n' "$out" | grep -q "^FOUND $1\$"; then echo "ok: reported: $1"
    else echo "FAIL: not reported: $1"; failed=1; fi
}
expect "outside symbol: time"
expect "weak symbol: getenv"
expect "writable data: sneaky_counter"
expect "writable data: sneaky_table"
case "$(uname -m)" in
    x86_64)
        expect "instruction: syscall"
        expect "instruction: rdtsc" ;;
esac

# The flags the core is compiled with must reject a variable-length array, and
# the same file must compile once -Wvla is taken out of them (so the rejection
# is for that reason and no other).
echo "core flags: $flags"
without=$(printf '%s' "$flags" | sed 's/-Wvla//')
if "$cc" $without -c "$vla" -o "$work/vla-control.o" 2>/dev/null; then echo "ok: the VLA file compiles without -Wvla"
else echo "FAIL: the VLA file does not compile even without -Wvla"; failed=1; fi
if "$cc" $flags -c "$vla" -o "$work/vla.o" 2>/dev/null; then echo "FAIL: the core's flags did not reject a variable-length array"; failed=1
else echo "ok: the core's flags reject a variable-length array"; fi

[ "$failed" -eq 0 ] && echo "PASS: the isolation check refuses the sneaky object for every reason it should"
exit "$failed"
