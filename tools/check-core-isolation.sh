#!/bin/sh
# Check what the compiled core library can reach and remember.
#
# What a pass proves, for the object code as built:
#   1. It calls nothing outside itself except the freestanding memory routines
#      memcpy, memcmp, memset, memmove, named exactly, or (in a --sanitized
#      build only) the memory checkers' instrumentation entry points, listed
#      exactly below. Those exact four names, and their bounds-checked forms
#      __memcpy_chk, __memset_chk, __memmove_chk, are the whole allowance:
#      __stpcpy_chk, memfrob or any other mem* or __*_chk is an outside call,
#      and so is any other function of the checkers' runtimes (a query such as
#      __sanitizer_get_current_allocated_bytes, a printer such as
#      __sanitizer_print_stack_trace), in every build. A call to fopen, time,
#      getenv, malloc, printf or anything else is an undefined symbol.
#   2. It has no weak references, no common symbols and no ifunc: a weak symbol
#      is a way to call something outside "only if it is there", a common
#      symbol is a global variable the linker allocates, and an ifunc runs a
#      resolver before main to choose what a symbol means. In a --sanitized
#      build the checkers' own weak and common symbols on the list are allowed.
#   3. It has no writable, mutable data: every section the loader may write to
#      is either empty or holds only relocated-then-read-only constants
#      (.data.rel.ro, the GOT). A non-empty .data, .data.rel, .bss, .tdata,
#      .tbss, a section of one's own, or an .init_array/.fini_array (code that
#      runs around main) fails. Nothing can carry state from one call, or one
#      simulated crash, to the next.
#   4. On x86 it contains none of the instructions that reach the operating
#      system, the machine's state, its clock (including the waits that end
#      at a time-stamp deadline) or its random source directly, wherever on
#      the disassembly line they appear (so a prefixed or hand-assembled form
#      is caught too). The list is below; it also refuses any access through
#      a segment register other than the compiler's own stack-protector read,
#      any call or jump to a fixed absolute address, and any x87 instruction
#      or use of an x87, MMX, SSE, AVX or mask register. Every thread-local
#      reference must name one of the checkers' thread-local variables.
#   5. With --sources: none of the core's translation units contains inline
#      assembly (`asm`, `__asm`, `__asm__`) or a checker's name, after the C
#      preprocessor has run (so token pasting and header includes are
#      resolved). Each unit is preprocessed with the flags given, and again
#      as a release build (-O2 -DNDEBUG), as a debug build (-O0 -UNDEBUG) and
#      as a sanitizer build (-fsanitize=address,undefined), so code behind
#      NDEBUG, __OPTIMIZE__ or a sanitizer's macro is seen too. The unit and
#      the project headers it includes must not test for a sanitizer at all
#      (__SANITIZE_*, __has_feature, __has_extension).
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
#   - Floating point on machines other than x86: kept out there only by
#     -mgeneral-regs-only. On x86 gcc refuses it under that flag; clang may
#     accept it, so point 4 refuses the registers it would use.
#   - An integer-to-function-pointer cast reached through -pedantic, and
#     variable-length arrays: kept out by the compiler (-std=c11 -pedantic
#     -Wvla -Werror), which refuses them.
#   - A pointer in .data.rel.ro written through a cast: writable at run time
#     only where the program is linked without RELRO.
#   - State left in dead stack memory and read back by a later call.
#   - Non-determinism of other kinds, and anything on machines other than x86
#     beyond points 1 to 3 and 5.
#   - In a --sanitized build the writable-section and init/fini tests are
#     skipped (the checkers add their own sections, unnamed), and %fs is
#     allowed at offset 0 or through a register, the forms MemorySanitizer
#     uses for its thread-local shadows, only when every thread-local
#     reference names one of its variables. %gs is refused there as well.
#     The 8 bytes clang's -fsanitize=function writes immediately before a
#     function (fe ca 05 c1 and a type hash) are not read as instructions
#     there, and only those: the window just before each function start of
#     the symbol table, when it begins with that magic.
#
# usage: check-core-isolation.sh [--sanitized] [--allow FILE] LIBRARY-OR-OBJECT
#            [--sources COMPILER "CFLAGS" FILE...]
# --allow FILE: further exact symbol names, one per line, that the library may
# call outside itself (the signing engine's calls into secp256k1-zkp and the
# core's action list, tools/signing-allowed-calls.txt). Still exact names.
# Prints one "FOUND" line per problem and exits 1 if there is any.
set -eu
sanitized=0
if [ "$1" = "--sanitized" ]; then sanitized=1; shift; fi
allow=""
if [ "${1:-}" = "--allow" ]; then allow="$2"; shift 2; fi
lib="$1"; shift
cc=""; cflags=""
if [ "${1:-}" = "--sources" ]; then shift; cc="$1"; cflags="$2"; shift 2; else set --; fi
found=0
report() { echo "FOUND $1: $2"; found=1; }

# The checkers' instrumentation entry points, by exact name or numbered family:
# what gcc and clang emit for the core under AddressSanitizer with
# UndefinedBehaviorSanitizer, and under MemorySanitizer. Nothing else of their
# runtimes. Allowed only in a --sanitized build.
checker_runtime='__asan_init|__asan_version_mismatch_check_v[0-9]+|__asan_(un)?register_(elf_)?globals'
checker_runtime="$checker_runtime|__asan_handle_no_return|__asan_option_detect_stack_use_after_return"
checker_runtime="$checker_runtime|__asan_report_(load|store)([0-9]+|_n)(_noabort)?|__asan_(load|store)([0-9]+|N)(_noabort)?"
checker_runtime="$checker_runtime|__asan_stack_(malloc|free)_[0-9]+|__asan_set_shadow_[0-9a-f][0-9a-f]|__asan_mem(cpy|set|move)"
checker_runtime="$checker_runtime|__asan_alloca_poison|__asan_allocas_unpoison|__asan_shadow_memory_dynamic_address"
checker_runtime="$checker_runtime|__asan_(un)?poison_stack_memory"
checker_runtime="$checker_runtime|__(start|stop)_asan_globals|___asan_globals_registered|__ubsan_handle_[a-z0-9_]+"
checker_runtime="$checker_runtime|__msan_init|__msan_chain_origin|__msan_set_alloca_origin(_with_descr|4)?|__msan_(un)?poison_alloca"
checker_runtime="$checker_runtime|__msan_warning(_noreturn|_with_origin|_with_origin_noreturn)?|__msan_maybe_warning_[0-9]+"
checker_runtime="$checker_runtime|__msan_maybe_store_origin_[0-9]+|__msan_mem(cpy|set|move)|__msan_track_origins|__msan_keep_going"
checker_tls='__msan_(param|retval|va_arg)(_origin)?_tls|__msan_va_arg_overflow_size_tls'
is_checker() { [ "$sanitized" -eq 1 ] && printf '%s\n' "$1" | grep -Eqx "$checker_runtime|$checker_tls"; }

# A symbol is an allowed outside reference only if it is one of these exact
# names (plus the checkers' entry points in a sanitized build).
allowed_outside() {
    case "$1" in
        memcpy|memcmp|memset|memmove) return 0 ;;
        __memcpy_chk|__memset_chk|__memmove_chk) return 0 ;;
        __stack_chk_fail|_GLOBAL_OFFSET_TABLE_) return 0 ;;
    esac
    if [ -n "$allow" ] && grep -qxF -- "$1" "$allow"; then return 0; fi
    is_checker "$1"
}

symbols=$(nm "$lib" | awk 'NF >= 2 { print $(NF-1), $NF }')
defined=$(printf '%s\n' "$symbols" | awk '$1 != "U" && $1 != "w" && $1 != "v" && $1 != "C" { print $2 }' | sort -u)

for sym in $(printf '%s\n' "$symbols" | awk '$1 == "U" { print $2 }' | sort -u); do
    allowed_outside "$sym" && continue
    printf '%s\n' "$defined" | grep -qx "$sym" && continue
    report "outside symbol" "$sym"
done

for sym in $(printf '%s\n' "$symbols" | awk '$1 == "w" || $1 == "v" || $1 == "W" || $1 == "V" { print $2 }' | sort -u); do
    is_checker "$sym" && continue
    report "weak symbol" "$sym"
done

# A common symbol: a global variable left for the linker to allocate (nm 'C',
# objdump *COM*). It is in no section, so the data tests below would miss it.
for sym in $(printf '%s\n' "$symbols" | awk '$1 == "C" { print $2 }' | sort -u); do
    is_checker "$sym" && continue                       # clang's ASan: ___asan_globals_registered
    report "common symbol" "$sym"
done

# An ifunc: nm marks it 'i'. Its code is chosen at load time by a resolver.
for sym in $(printf '%s\n' "$symbols" | awk '$1 == "i" || $1 == "I" { print $2 }' | sort -u); do
    report "ifunc" "$sym"
done

# Writable, mutable data: an object symbol in a section the loader may write to
# that is neither the relocated-then-read-only constants nor the GOT. No name
# is exempt, in any build. The list is computed first and reported in this
# shell: a `cmd | while` would set `found` only in a subshell and lose it.
for name in $(objdump -t "$lib" 2>/dev/null | awk -F'\t' '
        NF >= 2 && index($1, " O ") > 0 {
            nf = split($1, a, " "); sect = a[nf];
            if (sect !~ /^\.(data|bss|tdata|tbss)/) next;
            if (sect ~ /^\.(data\.rel\.ro|got)/) next;
            split($2, b, " "); print b[2];
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
        if [ "$sanitized" -eq 0 ]; then
            code=$(objdump -d "$lib" | awk -F'\t' 'NF >= 3 { print $3 }')
        else
            # clang's -fsanitize=function puts 8 bytes of data immediately
            # before each function it instruments: the magic 0xc105cafe
            # (fe ca 05 c1) and a hash of the function's type. objdump decodes
            # them as instructions, and a hash byte can read as a prefix such
            # as `fs`. In a sanitized build only, exactly those 8 bytes are
            # left out: the window [start - 8, start) of a function symbol of
            # the symbol table (type F), in the same member and section, when
            # the decoded lines cover it exactly and begin with the magic.
            # Bytes anywhere else, the same magic included, are checked.
            starts=$(objdump -t "$lib" | awk '
                /:     file format / { m = $0; sub(/:     file format .*/, "", m); next }
                length($0) > 25 && substr($0, 24, 1) == "F" && substr($0, 17, 1) == " " {
                    s = substr($0, 26); sub(/\t.*/, "", s); print m "\t" s "\t" substr($0, 1, 16) }')
            code=$(objdump -d "$lib" | GZ_STARTS="$starts" awk -F'\t' '
                function hex(h,   i, v, c) { v = 0; h = tolower(h)
                    for (i = 1; i <= length(h); i++) { c = index("0123456789abcdef", substr(h, i, 1)); if (!c) return -1; v = v * 16 + c - 1 }
                    return v }
                function flush(   i, k, s, lo, at, bytes, ok) {
                    for (k = 1; k <= nf; k++) {
                        s = fstart[k]; lo = s - 8; if (lo < 0) continue
                        at = lo; bytes = ""; ok = 1
                        for (i = 1; i <= n; i++) {
                            if (addr[i] + len[i] <= lo || addr[i] >= s) continue
                            if (addr[i] != at || addr[i] + len[i] > s) { ok = 0; break }
                            bytes = bytes raw[i]; at += len[i]
                        }
                        if (ok && at == s && substr(bytes, 1, 8) == "feca05c1")
                            for (i = 1; i <= n; i++) if (addr[i] >= lo && addr[i] < s) skip[i] = 1
                    }
                    for (i = 1; i <= n; i++) if (!skip[i] && ins[i] != "") print ins[i]
                    n = 0; split("", skip)
                }
                function section_begins(   j) {
                    nf = 0
                    for (j = 1; j <= ns; j++) if (sm[j] == mem && ss[j] == sec) fstart[++nf] = sa[j]
                }
                BEGIN { ns = split(ENVIRON["GZ_STARTS"], lines, "\n")
                        for (j = 1; j <= ns; j++) { split(lines[j], p, "\t"); sm[j] = p[1]; ss[j] = p[2]; sa[j] = hex(p[3]) } }
                /:     file format / { flush(); mem = $0; sub(/:     file format .*/, "", mem); next }
                /^Disassembly of section / { flush(); sec = $0; sub(/^Disassembly of section /, "", sec); sub(/:$/, "", sec); section_begins(); next }
                NF >= 2 && $1 ~ /^ *[0-9a-f]+:$/ {
                    a = $1; gsub(/[ :]/, "", a); b = $2; gsub(/ /, "", b)
                    n++; addr[n] = hex(a); raw[n] = tolower(b); len[n] = length(b) / 2; ins[n] = NF >= 3 ? $3 : ""
                    next }
                END { flush() }')
        fi
        # Instructions that reach the OS, the machine's state, its clock or its
        # random source. Matched anywhere on the line (prefixes, hand-assembled
        # bytes shown as a mnemonic), so a disguised form is caught too.
        banned='syscall|sysenter|sysexit[lq]?|sysret[lq]?|swapgs'            # the operating system
        banned="$banned|vmcall|vmmcall|vmfunc|enqcmds?"                      # the hypervisor, devices
        banned="$banned|rdtscp?|rdpmc|rdpid|rdpru"                           # the clock and the counters
        banned="$banned|tpause|umwait|umonitor"                              # waits until a time-stamp deadline
        banned="$banned|rdrand|rdseed"                                       # the random source
        banned="$banned|cpuid|xgetbv|xsetbv"                                 # what machine am I
        banned="$banned|rd(fs|gs)base|wr(fs|gs)base"                         # the thread pointers
        banned="$banned|xbegin|xend|xabort|xtest"                            # a hardware transaction
        banned="$banned|lsl|lar|sldt|sgdt|sidt|str|smsw|verr|verw"           # the descriptor tables
        banned="$banned|stmxcsr|vstmxcsr|rdsspq?|incsspq?|rdpkru|wrpkru"     # control and shadow-stack state
        banned="$banned|ptwrite[lq]?|f?xsave[a-z0-9]*|f?xrstor[a-z0-9]*"     # the processor trace, machine state
        for insn in $(printf '%s\n' "$code" | grep -Eow "$banned|int +\\\$0x80" | sed 's/ .*//' | sort -u); do
            report "instruction" "$insn"
        done
        # Thread-local references, in any build: only the checkers' own.
        tls=$(objdump -r "$lib" 2>/dev/null |
              awk '$2 ~ /^R_X86_64_(TPOFF|GOTTPOFF|TLS|DTPOFF|GOTPC32_TLSDESC)/ { print $3 }' |
              sed 's/[-+]0x[0-9a-f]*$//' | sort -u)
        for sym in $tls; do
            if [ "$sanitized" -eq 1 ] && printf '%s\n' "$sym" | grep -Eqx "$checker_tls"; then continue; fi
            report "thread-local reference" "$sym"
        done
        # Segment registers: only the canary read; in a sanitized build also
        # %fs at offset 0 or through a register, and only when every
        # thread-local reference is a checker's (tested just above). Every
        # other line, %gs included, is refused.
        segs=$(printf '%s\n' "$code" | grep -E '%[fg]s:' | grep -v '%fs:0x28' || true)
        if [ -n "$segs" ]; then
            if [ "$sanitized" -eq 0 ] || [ -z "$tls" ] ||
               printf '%s\n' "$segs" | grep -Ev '%fs:(0x0([^0-9a-fx(]|$)|-?(0x[0-9a-f]+)?\()' | grep -q .; then
                report "instruction" "segment register access"
            fi
        fi
        if printf '%s\n' "$code" | grep -Eq '\$0xffffffffff6[0-9a-f]{5}|\*0x[0-9a-f]{6,}'; then
            report "instruction" "call or jump to a fixed address"
        fi
        # Floating-point and vector registers, and x87 instructions (every x86
        # mnemonic that starts with f). The core's flags forbid them, but not
        # every compiler refuses floating point under -mgeneral-regs-only.
        if printf '%s\n' "$code" | grep -Eq '%(st|mm[0-7]|[xyz]mm[0-9]|k[0-7])|^[[:space:]]*((lock|rep[a-z]*|data16|addr32|bnd|notrack|cs|ds|es|ss) +)*f[a-z0-9]*([[:space:]]|$)'; then
            report "instruction" "floating-point or vector register"
        fi ;;
    *) echo "note: instruction scan skipped on $(uname -m)" ;;
esac

# The source scan. Each unit is preprocessed four ways (point 5), so token
# pasting, header includes and code behind NDEBUG, __OPTIMIZE__ or a
# sanitizer's macro are all resolved first. Needs the compiler and the core's
# flags. The raw text of the unit and of the project headers it includes is
# also searched for tests of a sanitizer.
for src in "$@"; do
    if [ -z "$cc" ]; then
        texts=$(cat "$src")
    else
        texts=""
        for extra in "" "-O2 -DNDEBUG" "-O0 -UNDEBUG" "-fno-sanitize=all -fsanitize=address,undefined"; do
            if ! text=$("$cc" $cflags $extra -E -P "$src" 2>/dev/null); then
                report "source scan" "$src could not be preprocessed with $cc $cflags $extra"
                continue 2
            fi
            texts="$texts
$text"
        done
    fi
    if printf '%s\n' "$texts" | grep -Eqw '__asm__|__asm|asm'; then
        report "inline assembly" "$src"
    fi
    if printf '%s\n' "$texts" | grep -Eq '\b__(asan|msan|ubsan|tsan|lsan|hwasan|dfsan|sanitizer)_|\b__(start|stop)_asan'; then
        report "checker name in source" "$src"
    fi
    files="$src"
    if [ -n "$cc" ]; then
        files=$("$cc" $cflags -MM "$src" 2>/dev/null | tr -d '\\' | sed 's/^[^:]*://') || files="$src"
    fi
    for f in $files; do
        if grep -Eq '__SANITIZE_|__has_feature|__has_extension' "$f"; then
            report "sanitizer test in source" "$f"
        fi
    done
done

if [ "$found" -ne 0 ]; then
    echo "FAIL: $lib is not isolated"
    exit 1
fi
echo "PASS: $lib calls nothing outside itself, holds no writable data, and has no system-call, clock, random or machine-state instructions"
