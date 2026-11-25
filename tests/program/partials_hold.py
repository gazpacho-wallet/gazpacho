#!/usr/bin/env python3
"""program_partials_hold (Slice 1 blocker C1; docs/notes/integration.md on the
integration branch, B17): a member whose partial signatures are out never
gives up the factory. A leave is refused while they are out; the host can
still fund the factory, and the member acks.

    python3 -I partials_hold.py PATH_TO_GAZPACHO_TEST WORK_DIR

One host and three AUTO members with a fixed tip (--tip, no chain), the
terms of program_signing with three seats. Member m1 drops every
round_complete it is sent (--test-drop-kind 74): its partial signatures are
out and the round cannot end on its side. Then the person asks m1 to leave
the lobby: refused now (409 too_late); the slot stays open, nothing is
aborted. m1 starts again without the drop: it acks, and the host reaches
Funding. (The pause's case, local-api.md 11.3, comes with the local-API
engine, PR 55.) Every process is checked for no node-error, repair or fatal
line.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import kill_all  # noqa: E402
from lobby import LEAVE, World, cmd, started, state  # noqa: E402
import signing  # noqa: E402

check = signing.check
TIP = signing.TIP
FUNDING = 4
ROUND_COMPLETE_KIND = 74


def leave_held(exe, work):
    name = "1 leave"
    w = World(exe, work, "case1")
    tick = ("--test-sign-tick-ms", "100")
    try:
        h = w.host("--tip", str(TIP), *tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts" % name):
            return
        t = signing.Terms(w.hkey, 900, target=3)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "%s: the lobby opens" % name)
        ms = {"m1": w.member("m1", "--member-signing", "auto", "--tip", str(TIP),
                             "--test-drop-kind", str(ROUND_COMPLETE_KIND), *tick)}
        for n in ("m2", "m3"):
            ms[n] = w.member(n, "--member-signing", "auto", "--tip", str(TIP), *tick)
        check(all(started(m) for m in ms.values()), "%s: three members start" % name)
        for n in ("m1", "m2", "m3"):
            w.join(ms[n], t)
        m1 = ms["m1"]
        check(m1.wait_for(r"test-drop kind=%d" % ROUND_COMPLETE_KIND, timeout=120) is not None,
              "%s: m1's partial signatures are out (the host's round_complete reached it, and was dropped)" % name)
        mk = m1.mark()
        m1.send(cmd(LEAVE, (12, t.scope)))
        r = m1.wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk)
        check(r is not None and r.group(1) == "409", "%s: a leave while partials are out: answered 409 (got %s)"
              % (name, r.group(1) if r else None))
        check(m1.count(r"too_late", start=mk) >= 1, "%s: the refusal says too_late" % name)
        time.sleep(2)
        check(m1.count(r"slot-closed scope=%s" % t.tag, start=mk) == 0, "%s: m1's slot stays open" % name)
        check(h.count(r"slot-closed scope=%s" % t.tag) == 0 and h.count(r"sign-member-left scope=%s" % t.tag) == 0,
              "%s: the host's lobby goes on, m1 still in it" % name)
        m1.stop()
        m1 = w.member("m1", "--member-signing", "auto", "--tip", str(TIP), *tick)
        check(started(m1), "%s: m1 starts again, without the drop" % name)
        check(m1.wait_for(r"sign-outcome scope=%s .*outcome=1 " % t.tag, timeout=90) is not None,
              "%s: m1 acks: Funding" % name)
        check(state(h, t, "host", FUNDING, timeout=60), "%s: the host reaches Funding: the factory is not abandoned" % name)
        check(m1.count(r"slot-closed scope=%s" % t.tag) == 0, "%s: m1's slot is still open after the restart" % name)
        w.clean(name)
    finally:
        kill_all(w.procs)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    leave_held(exe, work)
    return check.result("partials_hold", work)


if __name__ == "__main__":
    sys.exit(main())
