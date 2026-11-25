#!/bin/sh
# Kind 0xffff (GZ_SEND_KIND_RESERVED) marked a SEND that still held a whole
# message: the bridge of an engine not yet on links (composite-node.md, tasks
# T-P42-1 and T-P43-1). Both bridges are gone: the lobby's in P4.2, the
# signing engine's and the simulator's contract-v1 network in P4.3. This check
# fails if any of them appears again anywhere in the sources:
#   - the lobby's constant (GZ_LOBBY_SEND_WHOLE), the function that read a
#     peer's number back out of a bridged SEND, or the lobby naming the
#     Lightning message type again;
#   - the signing engine's constant (GZ_SIGN_SEND_WHOLE), its link helpers
#     (gz_sign_link_peer, gz_sign_link_set_peer), or a peer array in its round
#     definition;
#   - the simulator's whole-message network (whole_messages);
# and if a program given links a symbol of either bridge. The reserved kind
# itself stays reserved: the composite refuses it from any engine and the
# program never puts it on the wire (action.h).
#
#   sh tools/check-send-whole.sh SOURCE-DIR [PROGRAM...]
set -eu
src=$1
shift
fail=0
where="$src/core $src/program $src/ports $src/sim $src/tests $src/fuzz"
gone() {   # NAME PATTERN...
    name=$1; shift
    pats=""
    for p in "$@"; do pats="$pats -e $p"; done
    # shellcheck disable=SC2086
    found=$(grep -rIl $pats $where 2>/dev/null | grep -v '/tools/check-send-whole.sh$' || true)
    if [ -n "$found" ]; then
        echo "check-send-whole: the $name is back in:" >&2
        echo "$found" >&2
        fail=1
    else
        echo "check-send-whole: the $name is gone"
    fi
}
gone "lobby's SEND bridge" GZ_LOBBY_SEND_WHOLE gz_lobby_sent_peer
if grep -q 'GZ_LOBBY_MSG_TYPE' "$src/core/lobby/include/gazpacho/lobby.h"; then
    echo "check-send-whole: the lobby names the Lightning message type again: it sends kind, scope and records" >&2
    fail=1
fi
gone "signing engine's SEND bridge" GZ_SIGN_SEND_WHOLE gz_sign_link_peer gz_sign_link_set_peer
if grep -Eq 'peer\[GZ_SIGN_MAX_PARTICIPANTS\]' "$src/core/signing/include/gazpacho/signing.h"; then
    echo "check-send-whole: the signing engine names peers again: its links come from keys" >&2
    fail=1
fi
gone "simulator's whole-message network" whole_messages
for prog in "$@"; do
    if nm "$prog" 2>/dev/null | grep -Eq " [TtDdBbRr] (gz_sign_link_peer|gz_sign_link_set_peer|gz_lobby_sent_peer)$"; then
        echo "check-send-whole: $prog links a bridge function" >&2
        fail=1
    fi
done
exit $fail
