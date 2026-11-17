#!/bin/sh
# Kind 0xffff (GZ_SEND_KIND_RESERVED) marks a SEND that still holds a whole
# message: the bridge of an engine not yet on links (composite-node.md, tasks
# T-P42-1 and T-P43-1).
#
# The lobby's bridge (GZ_LOBBY_SEND_WHOLE) was deleted in P4.2, when the lobby
# went on links. This check fails if the constant, or the function that read
# a peer's number back out of a bridged SEND, appears again anywhere in the
# sources, or if the lobby names the Lightning message type again.
#
# The signing engine's bridge (GZ_SIGN_SEND_WHOLE) stands until P4.3. It must
# not reach a program: this check fails if a program links the signing engine
# while its bridge still exists, so the step that puts it on links cannot
# ship with the bridge.
#
#   sh tools/check-send-whole.sh SOURCE-DIR [PROGRAM...]
set -eu
src=$1
shift
fail=0
found=$(grep -rIl -e 'GZ_LOBBY_SEND_WHOLE' -e 'gz_lobby_sent_peer' \
        "$src/core" "$src/program" "$src/ports" "$src/sim" "$src/tests" "$src/fuzz" 2>/dev/null || true)
if [ -n "$found" ]; then
    echo "check-send-whole: the lobby's SEND bridge is back in:" >&2
    echo "$found" >&2
    fail=1
elif grep -q 'GZ_LOBBY_MSG_TYPE' "$src/core/lobby/include/gazpacho/lobby.h"; then
    echo "check-send-whole: the lobby names the Lightning message type again: it sends kind, scope and records" >&2
    fail=1
else
    echo "check-send-whole: the lobby bridge is gone"
fi
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
check "signing engine" "gz_sign_" "GZ_SIGN_SEND_WHOLE" "$src/core/signing/include/gazpacho/signing.h" "$src/core/signing/signing.c"
exit $fail
