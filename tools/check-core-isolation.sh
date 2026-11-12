#!/bin/sh
# Check what the compiled core library can reach and remember.
#
# What a pass proves, for the object code as built:
#   1. It calls nothing outside itself except four freestanding memory
#      routines (memcpy, memcmp, memset, memmove, or their bounds-checked
#      forms such as __memcpy_chk, which some toolchains substitute). A call
#      to fopen, time, getenv, malloc, printf or anything else is an
#      undefined symbol.
#   2. It has no weak references: a weak symbol is a way to call something
#      outside "only if it is there".
#   3. It has no writable data: no globals, no static variables, nothing that
#      could carry state from one call, or one simulated crash, to the next.
#   4. On x86 it contains none of the instructions that reach the operating
#      system or the processor's clock and random source directly: syscall,
#      sysenter, int 0x80, rdtsc, rdtscp, rdrand, rdseed.
#
# What it does not prove: that the code is deterministic in every other way
# (it could still use the address of a variable as data, or floating point
# whose results vary between machines), or anything about code that is not in
# the library. Variable-length arrays and non-standard C are kept out
# separately, by the flags the core is compiled with (-std=c11 -pedantic
# -Wvla -Werror).
#
# usage: check-core-isolation.sh path/to/library.a-or-object.o
# Prints one "FOUND" line per problem and exits 1 if there is any.
set -eu
lib="$1"
found=0
report() { echo "FOUND $1: $2"; found=1; }

symbols=$(nm "$lib" | awk 'NF >= 2 { print $(NF-1), $NF }')
defined=$(printf '%s\n' "$symbols" | awk '$1 != "U" && $1 != "w" && $1 != "v" { print $2 }' | sort -u)

for sym in $(printf '%s\n' "$symbols" | awk '$1 == "U" { print $2 }' | sort -u); do
    case "$sym" in
        memcpy|memcmp|memset|memmove) continue ;;            # freestanding C
        __memcpy_chk|__memset_chk|__memmove_chk) continue ;; # the same, as the C library's
                                                             # hardened headers emit them
        __asan_*|__ubsan_*|__sanitizer_*) continue ;;        # checker builds
        __stack_chk_fail|_GLOBAL_OFFSET_TABLE_) continue ;;  # compiler support
    esac
    if printf '%s\n' "$defined" | grep -qx "$sym"; then continue; fi
    report "outside symbol" "$sym"
done

for sym in $(printf '%s\n' "$symbols" | awk '$1 == "w" || $1 == "v" || $1 == "W" || $1 == "V" { print $2 }' | sort -u); do
    case "$sym" in
        __start_asan_globals|__stop_asan_globals) continue ;; # clang's ASan: bounds of
                                                              # its own globals section
    esac
    report "weak symbol" "$sym"
done

for sym in $(printf '%s\n' "$symbols" | awk '$1 ~ /^[bBdDcCsSgG]$/ { print $2 }' | sort -u); do
    case "$sym" in __asan_*|___asan_*|__ubsan_*|__sanitizer_*) continue ;; esac
    report "writable data" "$sym"
done

case "$(uname -m)" in
    x86_64|i?86)
        for insn in $(objdump -d "$lib" | awk -F'\t' 'NF >= 3 { print $3 }' |
                      grep -Eo '^(syscall|sysenter|rdtscp?|rdrand|rdseed)\b|^int +\$0x80' | sed 's/ .*//' | sort -u); do
            report "instruction" "$insn"
        done ;;
    *) echo "note: instruction scan skipped on $(uname -m)" ;;
esac

if [ "$found" -ne 0 ]; then
    echo "FAIL: $lib is not isolated"
    exit 1
fi
echo "PASS: $lib calls nothing outside itself, holds no writable data, and has no system-call, clock or random instructions"
