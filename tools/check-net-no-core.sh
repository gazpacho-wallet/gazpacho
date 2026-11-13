#!/bin/sh
# The transport includes no core header (contract v2, section 12): nothing
# under ports/net/ or tools/gz-net/ names a header of core/, and each of their
# sources compiles with an include path that has no core directory.
#
# usage: tools/check-net-no-core.sh CC SECP256K1_INCLUDE_DIR
set -u
cc="$1"; secp="$2"
root=$(cd "$(dirname "$0")/.." && pwd)
fail=0
if grep -n -E '#[[:space:]]*include[[:space:]]*[<"](gazpacho/|core/|\.\./)' \
        "$root"/ports/net/*.c "$root"/ports/net/*.h "$root"/tools/gz-net/*.c; then
    echo "FAIL: a core header (or a path out of ports/net) is included above"
    fail=1
fi
for f in "$root"/ports/net/*.c "$root"/tools/gz-net/*.c; do
    if ! "$cc" -std=c11 -fsyntax-only -I "$root/ports/net" -I "$secp" "$f"; then
        echo "FAIL: $f does not compile without the core's include directory"
        fail=1
    fi
done
[ $fail -eq 0 ] && echo "RESULT: PASS (ports/net and gz-net need no core header)"
exit $fail
