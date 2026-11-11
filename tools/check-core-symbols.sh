#!/bin/sh
# Check that the core library calls nothing outside itself except a few
# freestanding memory routines. This is how "the core never touches the
# operating system" is enforced: a call to fopen, time, getenv, malloc, printf
# or anything else shows up here as an undefined symbol and fails the test.
#
# usage: check-core-symbols.sh path/to/libgazpacho_core.a
set -eu
lib="$1"
defined=$(nm --defined-only "$lib" | awk 'NF==3 {print $3}' | sort -u)
bad=""
for sym in $(nm -u "$lib" | awk '$1=="U" {print $2}' | sort -u); do
    case "$sym" in
        memcpy|memcmp|memset|memmove) continue ;;          # freestanding C
        __asan_*|__ubsan_*|__sanitizer_*) continue ;;      # checker builds
        __stack_chk_fail|_GLOBAL_OFFSET_TABLE_) continue ;; # compiler support
    esac
    if printf '%s\n' "$defined" | grep -qx "$sym"; then continue; fi
    bad="$bad $sym"
done
if [ -n "$bad" ]; then
    echo "FAIL: the core library refers to outside symbols:$bad"
    exit 1
fi
echo "PASS: the core library refers to nothing outside itself"
