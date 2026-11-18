#!/usr/bin/env python3
"""program_ack_depth (docs/notes/integration.md, B16; review B of PR 52, M1):
a member that restarts between saving its partial signatures and the
host's round_complete judges its ack at its real depth in the tree.

    python3 -I ack_depth.py PATH_TO_GAZPACHO_TEST WORK_DIR

One host and three AUTO members with a fixed tip (--tip, no chain), the
terms of program_signing with three seats. Member m1 stops once the batch holding its
partial signatures (round_signed) is durable (--test-crash-after-record),
and starts again on its folder with another tip. The ack check
(gz_tree_may_ack, safety-rule.md C8) is then
    ack tip <= E - 2*d*STEP - (d + 3)*A - M - 2*B - funding deadline
with E the end height the host proposed (its tip + lifetime + wind-down),
STEP 5 and Slice 1's signet constants A 6, B 3, M 14, a funding deadline
of 36 blocks: E - 16*d - 74 for a leaf at depth d. Every member of a T1
tree sits at depth 1 or more.

  1. Started again at TIP + 5, inside the limit at any depth here: it acks
     (round_completed saved) and reaches Funding.
  2. Started again at E - 80: past the limit at depth 1 or more, inside it
     at depth 0. It must refuse (Retry, no round_completed). Judged at a
     depth of 0 (the depth not kept across a restart), it acks.
Every process is checked for no node-error, repair or fatal line.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import kill_all  # noqa: E402
import lobby  # noqa: E402
from lobby import World, parse_tlv, started, state  # noqa: E402
import signing  # noqa: E402

check = signing.check
TIP = signing.TIP
ROUND_SIGNED, ROUND_COMPLETED = signing.ROUND_SIGNED, signing.ROUND_COMPLETED
FUNDING = 4


def end_height(t):
    """The end height the host proposes at TIP: its tip + lifetime + wind-down (signslot.c)."""
    v = dict(parse_tlv(t.outer))
    return TIP + struct.unpack(">I", v[26])[0] + struct.unpack(">I", v[28])[0]


def restart(exe, work, name, tip_after, acks):
    w = World(exe, work, "case" + name.split()[0])   # a folder name with no spaces
    tick = ("--test-sign-tick-ms", "100")
    try:
        h = w.host("--tip", str(TIP), *tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts" % name):
            return
        t = signing.Terms(w.hkey, 900, target=3)   # three seats: the round begins once the three are ready
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "%s: the lobby opens" % name)
        ms = {"m1": w.member("m1", "--member-signing", "auto", "--tip", str(TIP),
                             "--test-crash-after-record", "%08x" % ROUND_SIGNED, *tick)}
        for n in ("m2", "m3"):
            ms[n] = w.member(n, "--member-signing", "auto", "--tip", str(TIP), *tick)
        check(all(started(m) for m in ms.values()), "%s: three members start" % name)
        for n in ("m1", "m2", "m3"):
            w.join(ms[n], t)
        m1 = ms["m1"]
        check(m1.wait_for(r"test-crash after-record type=%08x" % ROUND_SIGNED, timeout=120) is not None,
              "%s: m1 stops once its partial signatures are saved" % name)
        m1.exit_code(timeout=30)
        check(m1.count(r"sign-outcome scope=%s " % t.tag) == 0, "%s: m1 had not acked before it stopped" % name)
        m1 = w.member("m1", "--member-signing", "auto", "--tip", str(tip_after), *tick)
        check(started(m1), "%s: m1 starts again at tip %d (TIP %+d)" % (name, tip_after, tip_after - TIP))
        if acks:
            check(m1.wait_for(r"sign-outcome scope=%s .*outcome=1 " % t.tag, timeout=90) is not None,
                  "%s: inside its limit, m1 acks: Funding" % name)
            check(state(h, t, "host", FUNDING, timeout=60), "%s: the host reaches Funding" % name)
        else:
            check(m1.wait_for(r"sign-outcome scope=%s .*outcome=2 " % t.tag, timeout=90) is not None,
                  "%s: past its limit at its real depth, m1 refuses to ack: Retry" % name)
            check(m1.count(r"sign-outcome scope=%s .*outcome=1 " % t.tag) == 0,
                  "%s: m1 never acks that round" % name)
        w.clean(name)
        w.stop()
        j = w.journal("m1")
        if acks:
            check(any(ROUND_COMPLETED in b for b in j), "%s: m1 saved round_completed (its ack)" % name)
        else:
            check(all(ROUND_COMPLETED not in b for b in j), "%s: m1 saved no round_completed" % name)
    finally:
        kill_all(w.procs)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    e = end_height(signing.Terms("02" + "00" * 32, 900))
    restart(exe, work, "1 restart inside the limit", TIP + 5, acks=True)
    restart(exe, work, "2 restart past the limit", e - 80, acks=False)
    return check.result("ack_depth", work)


if __name__ == "__main__":
    sys.exit(main())
