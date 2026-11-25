#!/bin/sh
# No built program holds the signer's vectors build (review A of #71, N1;
# decision K20): nm must not find gz_sg_vectors_build_never_ship, nor any
# gz_sgv_* entry point, in any of the files given.
#
# usage: never_ship.sh FILE...                 every FILE must be clean
#        never_ship.sh --expect-marker FILE    FILE must hold the marker (the
#                                              check's own test)
set -eu
expect=0
if [ "${1:-}" = --expect-marker ]; then expect=1; shift; fi
[ $# -gt 0 ] || { echo "FAIL: no files given"; exit 1; }
fail=0
n=0
for f in "$@"; do
    syms=$(nm "$f" 2>/dev/null | awk '{print $NF}') || { echo "FAIL: nm cannot read $f"; fail=1; continue; }
    [ -n "$syms" ] || { echo "FAIL: nm found no symbols in $f (stripped?)"; fail=1; continue; }
    n=$((n + 1))
    if echo "$syms" | grep -q -e '^gz_sg_vectors_build_never_ship$' -e '^gz_sgv_'; then
        if [ $expect -eq 0 ]; then echo "FAIL: $f holds the signer's vectors build"; fail=1; fi
    elif [ $expect -eq 1 ]; then
        echo "FAIL: $f lacks the marker: the check would not see the vectors build"; fail=1
    fi
done
[ $fail -eq 0 ] && echo "never ship: $n files checked"
exit $fail
