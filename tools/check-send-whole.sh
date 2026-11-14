#!/bin/sh
# The lobby's SEND bridge (kind 0xffff, GZ_LOBBY_SEND_WHOLE) is a stopgap
# until P4.2 puts the lobby on links (composite-node.md, task T-P42-1). It
# must never reach a program: this check fails if a program links the lobby
# while the constant still exists, so P4.2 cannot ship with it.
#
#   sh tools/check-send-whole.sh SOURCE-DIR PROGRAM...
set -eu
src=$1
shift
if ! grep -q 'GZ_LOBBY_SEND_WHOLE' "$src/core/lobby/include/gazpacho/lobby.h" "$src/core/lobby/act.c" 2>/dev/null; then
    echo "check-send-whole: the bridge is gone"
    exit 0
fi
for prog in "$@"; do
    if nm "$prog" 2>/dev/null | grep -q ' [TtDdBbRr] gz_lobby_'; then
        echo "check-send-whole: $prog links the lobby while GZ_LOBBY_SEND_WHOLE (kind 0xffff) still exists: remove it (task T-P42-1)" >&2
        exit 1
    fi
done
echo "check-send-whole: the bridge exists and no program links the lobby"
