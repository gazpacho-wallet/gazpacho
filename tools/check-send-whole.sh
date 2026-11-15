#!/bin/sh
# The lobby's SEND bridge (kind 0xffff, GZ_LOBBY_SEND_WHOLE) was a stopgap
# until P4.2 put the lobby on links (composite-node.md, task T-P42-1). P4.2
# deleted it. This check fails if the constant, or the function that read a
# peer's number back out of a bridged SEND, appears again anywhere in the
# sources, and if the lobby's header still describes whole Lightning messages.
#
#   sh tools/check-send-whole.sh SOURCE-DIR
set -eu
src=$1
found=$(grep -rIl -e 'GZ_LOBBY_SEND_WHOLE' -e 'gz_lobby_sent_peer' \
        "$src/core" "$src/program" "$src/ports" "$src/sim" "$src/tests" "$src/fuzz" 2>/dev/null || true)
if [ -n "$found" ]; then
    echo "check-send-whole: the lobby's SEND bridge is back in:" >&2
    echo "$found" >&2
    exit 1
fi
if grep -q 'GZ_LOBBY_MSG_TYPE' "$src/core/lobby/include/gazpacho/lobby.h"; then
    echo "check-send-whole: the lobby names the Lightning message type again: it sends kind, scope and records" >&2
    exit 1
fi
echo "check-send-whole: the bridge is gone"
