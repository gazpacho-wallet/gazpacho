#!/bin/sh
# Check what the compiled core library can reach and remember.
#
# What a pass proves, for the object code as built:
#   1. It calls nothing outside itself except the freestanding memory routines
#      memcpy, memcmp, memset, memmove, named exactly, or (in a --sanitized
#      build only) the memory checkers' own helpers. Those exact four names,
#      and their bounds-checked forms __memcpy_chk, __memset_chk, __memmove_chk,
#      are the whole allowance: __stpcpy_chk, memfrob or any other mem* or
#      __*_chk is an outside call. A call to fopen, time, getenv, malloc,
#      printf or anything else is an undefined symbol.
#   2. It has no weak references and no ifunc: a weak symbol is a way to call
#      something outside "only if it is there", and an ifunc runs a resolver
#      before main to choose what a symbol means.
#   3. It has no writable, mutable data: every section the loader may write to
#      is either empty or holds only relocated-then-read-only constants
#      (.data.rel.ro, the GOT). A non-empty .data, .bss, .tdata, .tbss, a
#      section of one's own, or an .init_array/.fini_array (code that runs
#      around main) fails. Nothing can carry state from one call, or one
#      simulated crash, to the next.
#   4. On x86 it contains none of the instructions that reach the operating
#      system, the machine's state, its clock or its random source directly,
#      wherever on the disassembly line they appear (so a prefixed or
#      hand-assembled form is caught too). The list is below; it also refuses
#      any access through a segment register other than the compiler's own
#      stack-protector read, and any call or jump to a fixed absolute address.
#   5. With --sources, after the C preprocessor has run (so token pasting and
#      header includes are resolved): none of the core's translation units
#      contains inline assembly.
#
# WHAT IT DOES NOT CATCH, and why:
#   - An address used as data (of a local, a function, or the return address),
#     and a read of the stack-protector canary (%fs:0x28): these look like
#     ordinary pointer arithmetic or the compiler's own code.
#   - An integer value cast to a function pointer and called (so a fixed
#     address, such as the vsyscall page, assembled at run time): in the
#     object this is indistinguishable from the legitimate indirect calls the
#     core makes through its ports and executor. The core contains no such
#     cast; that is kept out by review, not by this script.
#   - Floating point: kept out instead by -mgeneral-regs-only, which makes the
#     compiler refuse it.
#   - An integer-to-function-pointer cast reached through -pedantic, and
#     variable-length arrays: kept out by the compiler (-std=c11 -pedantic
#     -Wvla -Werror), which refuses them.
#   - Non-determinism of other kinds, and anything on machines other than x86
#     beyond points 1 to 3 and 5.
#   - In a --sanitized build the writable-section test is skipped (the checkers
#     add their own); the symbol and instruction tests still run.
#
# usage: check-core-isolation.sh [--sanitized] LIBRARY-OR-OBJECT
#            [--sources COMPILER "CFLAGS" FILE...]
# Prints one "FOUND" line per problem and exits 1 if there is any.
set -eu
sanitized=0
if [ "$1" = "--sanitized" ]; then sanitized=1; shift; fi
lib="$1"; shift
cc=""; cflags=""
if [ "${1:-}" = "--sources" ]; then shift; cc="$1"; cflags="$2"; shift 2; else set --; fi
found=0
report() { echo "FOUND $1: $2"; found=1; }

# A symbol is an allowed outside reference only if it is one of these exact
# names (plus the checkers' helpers in a sanitized build).
allowed_outside() {
    case "$1" in
        memcpy|memcmp|memset|memmove) return 0 ;;
        __memcpy_chk|__memset_chk|__memmove_chk) return 0 ;;
        __stack_chk_fail|_GLOBAL_OFFSET_TABLE_) return 0 ;;
    esac
    if [ "$sanitized" -eq 1 ]; then
        case "$1" in __asan_*|__ubsan_*|__sanitizer_*) return 0 ;; esac
    fi
    return 1
}

symbols=$(nm "$lib" | awk 'NF >= 2 { print $(NF-1), $NF }')
defined=$(printf '%s\n' "$symbols" | awk '$1 != "U" && $1 != "w" && $1 != "v" { print $2 }' | sort -u)

for sym in $(printf '%s\n' "$symbols" | awk '$1 == "U" { print $2 }' | sort -u); do
    allowed_outside "$sym" && continue
    printf '%s\n' "$defined" | grep -qx "$sym" && continue
    report "outside symbol" "$sym"
done

for sym in $(printf '%s\n' "$symbols" | awk '$1 == "w" || $1 == "v" || $1 == "W" || $1 == "V" { print $2 }' | sort -u); do
    report "weak symbol" "$sym"
done

# An ifunc: nm marks it 'i'. Its code is chosen at load time by a resolver.
for sym in $(printf '%s\n' "$symbols" | awk '$1 == "i" || $1 == "I" { print $2 }' | sort -u); do
    report "ifunc" "$sym"
done

# Writable, mutable data: an object symbol in a section the loader may write to
# that is neither the relocated-then-read-only constants nor the GOT. The list
# is computed first and reported in this shell: a `cmd | while` would set
# `found` only in a subshell and lose it.
for name in $(objdump -t "$lib" 2>/dev/null | awk -F'\t' -v san="$sanitized" '
        NF >= 2 && index($1, " O ") > 0 {
            nf = split($1, a, " "); sect = a[nf];
            if (sect !~ /^\.(data|bss|tdata|tbss)/) next;
            if (sect ~ /^\.(data\.rel\.ro|got)/) next;
            split($2, b, " "); name = b[2];
            if (san == "1" && name ~ /^(__asan_|__ubsan_|__sanitizer_)/) next;
            print name;
        }' | sort -u); do
    report "writable data" "$name"
done

if [ "$sanitized" -eq 0 ]; then
    for sec in $(readelf -SW "$lib" | sed 's/^ *\[ *[0-9]*\] *//' |
                 awk '$1 ~ /^\.(init|fini)_array/ { print $1 }' | sort -u); do
        report "init/fini array" "$sec"
    done
    for sc in $(readelf -SW "$lib" | sed 's/^ *\[ *[0-9]*\] *//' |
                awk '($1 ~ /^\./ || NF >= 7) && $7 ~ /W/ && $5 !~ /^0+$/ &&
                     $1 !~ /^\.(init|fini)_array/ && $1 !~ /^\.(data\.rel\.ro|got)/ { print $1 ":" $5 }' | sort -u); do
        report "writable section" "${sc%%:*} (size 0x${sc##*:})"
    done
fi

case "$(uname -m)" in
    x86_64|i?86)
        code=$(objdump -d "$lib" | awk -F'\t' 'NF >= 3 { print $3 }')
        # Instructions that reach the OS, the machine's state, its clock or its
        # random source. Matched anywhere on the line (prefixes, hand-assembled
        # bytes shown as a mnemonic), so a disguised form is caught too.
        banned='syscall|sysenter|sysexit|sysret|swapgs'                      # the operating system
        banned="$banned|rdtscp?|rdpmc|rdpid"                                 # the clock and the counters
        banned="$banned|rdrand|rdseed"                                       # the random source
        banned="$banned|cpuid|xgetbv|xsetbv"                                 # what machine am I
        banned="$banned|rd(fs|gs)base|wr(fs|gs)base"                         # the thread pointers
        banned="$banned|xbegin|xend|xabort|xtest"                            # a hardware transaction
        banned="$banned|lsl|lar|sldt|sgdt|sidt|str|smsw|verr|verw"           # the descriptor tables
        banned="$banned|stmxcsr|vstmxcsr|rdsspq?|incsspq?|rdpkru"            # control and shadow-stack state
        for insn in $(printf '%s\n' "$code" | grep -Eow "$banned|int +\\\$0x80" | sed 's/ .*//' | sort -u); do
            report "instruction" "$insn"
        done
        if printf '%s\n' "$code" | grep -E '%[fg]s:' | grep -qv '%fs:0x28'; then
            report "instruction" "segment register access"
        fi
        if printf '%s\n' "$code" | grep -Eq '\$0xffffffffff6[0-9a-f]{5}|\*0x[0-9a-f]{6,}'; then
            report "instruction" "call or jump to a fixed address"
        fi ;;
    *) echo "note: instruction scan skipped on $(uname -m)" ;;
esac

# The source scan, over the C preprocessor's output, so token pasting and
# header includes are resolved first. Needs the compiler and the core's flags.
for src in "$@"; do
    if [ -n "$cc" ]; then
        if ! text=$("$cc" $cflags -E -P "$src" 2>/dev/null); then
            report "source scan" "$src could not be preprocessed with $cc $cflags"
            continue
        fi
    else
        text=$(cat "$src")
    fi
    if printf '%s\n' "$text" | grep -Eqw '__asm__|__asm|asm'; then
        report "inline assembly" "$src"
    fi
done

if [ "$found" -ne 0 ]; then
    echo "FAIL: $lib is not isolated"
    exit 1
fi
echo "PASS: $lib calls nothing outside itself, holds no writable data, and has no system-call, clock, random or machine-state instructions"
