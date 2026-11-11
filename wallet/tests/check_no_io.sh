#!/bin/sh
# The key library does no I/O, reads no randomness or clock and has no global
# state.  usage: check_no_io.sh libgazpacho_wallet_keys.a
lib="$1"
bad=0
# Undefined symbols the library asks the outside for.
undef=$(nm -u "$lib" | awk '$1 == "U" {print $2}' | sort -u)
for s in $undef; do
  case "$s" in
    fopen*|fread|fwrite|fprintf|printf|puts|fputs|fclose|open|open64|read|write|close|\
    socket|connect|send|recv|time|clock|clock_gettime|gettimeofday|rand|random|srand|\
    getrandom|getentropy|arc4random*|RAND_bytes|RAND_priv_bytes|getenv|system|malloc|calloc|realloc|free)
      echo "FAIL: library uses $s"; bad=1 ;;
  esac
done
# Writable data in the library would be global state (b/B bss, d/D data, C common).
# One exception: bip39_wordlist_en, the imported word list (core/superscalar/src/
# bip39_wordlist.h).  It is declared there as an array of non-const pointers, so
# the compiler places it in a data section; nothing writes to it.  Names added by
# the sanitizers are skipped.
state=$(nm "$lib" | awk '$2 ~ /^[bBdDC]$/ {print $3}' | grep -v -e '^bip39_wordlist_en$' -e '^__asan' -e '^__ubsan' -e '^__odr_asan' -e '^\.' -e '^\*\.' || true)
if [ -n "$state" ]; then echo "FAIL: library has writable global data: $state"; bad=1; fi
[ "$bad" = 0 ] && echo "check_no_io: library asks for no I/O, randomness, clock or heap, and has no global state"
exit $bad
