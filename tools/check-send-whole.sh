#!/bin/sh
# Kind 0xffff (GZ_SEND_KIND_RESERVED) marks a SEND that still holds a whole
# message: the lobby's bridge until P4.2 (GZ_LOBBY_SEND_WHOLE) and the signing
# engine's until P4.3 (GZ_SIGN_SEND_WHOLE); composite-node.md, tasks T-P42-1
# and T-P43-1. Neither may reach a program: this check fails if a program
# links the lobby or the signing engine while its bridge still exists, so the
# step that puts an engine on links cannot ship with its bridge.
#
#   sh tools/check-send-whole.sh SOURCE-DIR PROGRAM...
set -eu
src=$1
shift
fail=0
check() {   # NAME SYMBOL-PREFIX CONSTANT FILE...
    name=$1; prefix=$2; constant=$3; shift 3
    if ! grep -q "$constant" "$@" 2>/dev/null; then
        echo "check-send-whole: the $name bridge is gone"
        return
    fi
    for prog in $PROGRAMS; do
        if nm "$prog" 2>/dev/null | grep -q " [TtDdBbRr] $prefix"; then
            echo "check-send-whole: $prog links the $name while $constant (kind 0xffff) still exists: remove the bridge" >&2
            fail=1
        fi
    done
    echo "check-send-whole: the $name bridge exists and no program links the $name"
}
PROGRAMS="$*"
check "lobby" "gz_lobby_" "GZ_LOBBY_SEND_WHOLE" "$src/core/lobby/include/gazpacho/lobby.h" "$src/core/lobby/act.c"
check "signing engine" "gz_sign_" "GZ_SIGN_SEND_WHOLE" "$src/core/signing/include/gazpacho/signing.h" "$src/core/signing/signing.c"
exit $fail
