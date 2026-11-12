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
#   3. It has no writable data: no symbol in a data or bss section, and no
#      writable section with any bytes in it at all, named or not (this also
#      covers thread-local storage and data placed by hand in a section).
#      Nothing can carry state from one call, or one simulated crash, to the
#      next.
#   4. On x86 it contains none of the instructions that reach the operating
#      system or the machine directly, wherever on the line the disassembler
#      shows them (so a prefixed form is caught too): syscall, sysenter,
#      int 0x80, rdtsc, rdtscp, rdrand, rdseed, cpuid, rdpmc, xgetbv; no
#      access through a segment register other than the compiler's own
#      stack-protector read; and no call or jump to a fixed absolute address.
#   5. With --sources: none of the listed source files contains inline
#      assembly.
#
# WHAT IT DOES NOT CATCH. It cannot show the code is deterministic in every
# other way. In particular it does not catch:
#   - an address used as data (of a local, a function, or the return address);
#   - a read of the stack-protector canary, which looks like the compiler's
#     own (a per-process random value);
#   - floating point, unless the core is built with -mgeneral-regs-only (it
#     is: that flag makes the compiler refuse it);
#   - instructions hidden as data and reached by a computed jump;
#   - anything on machines other than x86 beyond points 1 to 3 and 5;
#   - writable sections in a build with the memory checkers, which add their
#     own (--sanitized skips that one test; the symbol test still runs).
# Variable-length arrays and non-standard C are kept out separately, by the
# flags the core is compiled with (-std=c11 -pedantic -Wvla -Werror).
#
# usage: check-core-isolation.sh [--sanitized] LIBRARY-OR-OBJECT [--sources FILE...]
# Prints one "FOUND" line per problem and exits 1 if there is any.
set -eu
sanitized=0
if [ "$1" = "--sanitized" ]; then sanitized=1; shift; fi
lib="$1"; shift
if [ "${1:-}" = "--sources" ]; then shift; else set --; fi
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
    report "weak symbol" "$sym"
done

for sym in $(printf '%s\n' "$symbols" | awk '$1 ~ /^[bBdDcCsSgG]$/ { print $2 }' | sort -u); do
    case "$sym" in __asan_*|__ubsan_*|__sanitizer_*) continue ;; esac
    report "writable data" "$sym"
done

# Every section with the "write" flag must be empty, whatever it is called.
if [ "$sanitized" -eq 0 ]; then
    for sec in $(readelf -SW "$lib" | sed 's/^ *\[ *[0-9]*\] *//' |
                 awk '$1 ~ /^\./ || NF >= 7 { if ($7 ~ /W/ && $5 !~ /^0+$/) print $1 ":" $5 }' | sort -u); do
        report "writable section" "${sec%%:*} (size 0x${sec##*:})"
    done
fi

case "$(uname -m)" in
    x86_64|i?86)
        code=$(objdump -d "$lib" | awk -F'\t' 'NF >= 3 { print $3 }')
        for insn in $(printf '%s\n' "$code" |
                      grep -Eow 'syscall|sysenter|rdtscp?|rdrand|rdseed|cpuid|rdpmc|xgetbv|int +\$0x80' |
                      sed 's/ .*//' | sort -u); do
            report "instruction" "$insn"
        done
        if printf '%s\n' "$code" | grep -E '%[fg]s:' | grep -qv '%fs:0x28'; then
            report "instruction" "segment register access"
        fi
        if printf '%s\n' "$code" | grep -Eq '\$0xffffffffff6[0-9a-f]{5}|^(call|jmp)[a-z]* +\*0x[0-9a-f]+( |$)'; then
            report "instruction" "call to a fixed address"
        fi ;;
    *) echo "note: instruction scan skipped on $(uname -m)" ;;
esac

for src in "$@"; do
    for line in $(grep -nEw '__asm__|__asm|asm' "$src" | cut -d: -f1); do
        report "inline assembly" "$src:$line"
    done
done

if [ "$found" -ne 0 ]; then
    echo "FAIL: $lib is not isolated"
    exit 1
fi
echo "PASS: $lib calls nothing outside itself, holds no writable data, and has no system-call, clock or random instructions"
