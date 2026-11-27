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
import re
import shutil
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
        mk, hk = m1.mark(), h.mark()
        m1.send(cmd(LEAVE, (12, t.scope)))
        r = m1.wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk)
        check(r is not None and r.group(1) == "409", "%s: a leave while partials are out: answered 409 (got %s)"
              % (name, r.group(1) if r else None))
        check(m1.count(r"too_late", start=mk) >= 1, "%s: the refusal says too_late" % name)
        time.sleep(2)
        check(m1.count(r"slot-closed scope=%s" % t.tag, start=mk) == 0, "%s: m1's slot stays open" % name)
        # What the host received: no leave (its seat count would drop: joined below 3), and its lobby goes on.
        check(h.count(r"lobby scope=%s\S* role=host state=\d+ joined=[012] " % t.tag, start=hk) == 0,
              "%s: the host received no leave: m1 is still seated" % name)
        check(h.count(r"slot-closed scope=%s" % t.tag) == 0, "%s: the host's lobby goes on" % name)
        m1.stop()
        m1 = w.member("m1", "--member-signing", "auto", "--tip", str(TIP), *tick)
        check(started(m1), "%s: m1 starts again, without the drop" % name)
        # Right after the start, from the journal: still refused.
        mk2 = m1.mark()
        m1.send(cmd(LEAVE, (12, t.scope)))
        r2 = m1.wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk2)
        check(r2 is not None and r2.group(1) == "409", "%s: a leave right after the restart: answered 409 (got %s)"
              % (name, r2.group(1) if r2 else None))
        check(m1.wait_for(r"sign-outcome scope=%s .*outcome=1 " % t.tag, timeout=90) is not None,
              "%s: m1 acks: Funding" % name)
        check(state(h, t, "host", FUNDING, timeout=60), "%s: the host reaches Funding: the factory is not abandoned" % name)
        check(m1.count(r"slot-closed scope=%s" % t.tag) == 0, "%s: m1's slot is still open after the restart" % name)
        w.clean(name)
    finally:
        kill_all(w.procs)


def journal_file(w, who):
    """The member's journal file (the stand-in's GZJSTAND file)."""
    for root, _, files in os.walk(os.path.join(w.work, who)):
        for f in files:
            path = os.path.join(root, f)
            with open(path, "rb") as fh:
                if fh.read(8) == b"GZJSTAND":
                    return path
    return None


def restore_mid_round(exe, work):
    """Case 2, K1 (BD2; review A of #98, M1): m1 restored from its words while its round is in flight (its
    partial signatures out, the host's round_complete dropped). The restored node has a new epoch: the
    old seat's round is dropped before the signing engine resumes. No secret of the old epoch is derived,
    no nonce made, nothing sent for the lobby (no resend of the round's saved messages either), and the
    person is told the seat was lost."""
    name = "2 restore mid-round"
    w = World(exe, work, "case2")
    tick = ("--test-sign-tick-ms", "100")
    try:
        h = w.host("--tip", str(TIP), *tick)
        if not check(started(h) and w.hkey is not None, "%s: the host starts" % name):
            return
        t = signing.Terms(w.hkey, 900, target=3)
        w.open(h, t)
        check(h.wait_for(r"slot-opened scope=%s .*role=host" % t.tag, timeout=10) is not None, "%s: the lobby opens" % name)
        ms = {"m1": w.member("m1", "--member-signing", "auto", "--tip", str(TIP), "--test-log-sends", "1",
                             "--test-drop-kind", str(ROUND_COMPLETE_KIND), *tick)}
        for n in ("m2", "m3"):
            ms[n] = w.member(n, "--member-signing", "auto", "--tip", str(TIP), *tick)
        check(all(started(m) for m in ms.values()), "%s: three members start" % name)
        for n in ("m1", "m2", "m3"):
            w.join(ms[n], t)
        m1 = ms["m1"]
        check(m1.wait_for(r"test-drop kind=%d" % ROUND_COMPLETE_KIND, timeout=120) is not None,
              "%s: m1's round is in flight (partials out, the host's round_complete dropped)" % name)
        e = m1.wait_for(r"key-epoch seq=\d+ epoch=([0-9a-f]{8})", timeout=5)
        e0 = e.group(1) if e else None
        check(e0 is not None, "%s: m1's epoch before the restore is known" % name)
        check(m1.count(r"key-secret epoch=%s" % e0) >= 1, "%s: m1 derived its keys for the round (the control)" % name)
        m1.stop()
        src = journal_file(w, "m1")
        check(src is not None, "%s: m1's journal is found" % name)
        if not src or not e0:
            return
        words = os.path.join(w.work, "m1-words.jrn")
        shutil.copyfile(src, words)                       # the backup: the journal as it stands (the device keeps its guard file)
        m1 = w.member("m1", "--member-signing", "auto", "--tip", str(TIP), "--test-log-sends", "1",
                      "--test-restore-from", words, *tick)
        check(started(m1), "%s: m1 starts again, restored from its words" % name)
        mk_r = m1.mark()
        r = m1.wait_for(r"restore-batch seq=\d+ epoch=([0-9a-f]{8})", timeout=10)
        check(r is not None and r.group(1) != e0, "%s: the restore draws a new epoch" % name)
        check(m1.wait_for(r"lobby-left-out scope=%s\S* .*why=stale_epoch" % t.tag, timeout=20) is not None,
              "%s: the old seat is left out, the person told (why=stale_epoch)" % name)
        time.sleep(5)                                     # several signing ticks (100 ms) and lobby timers
        check(m1.count(r"key-secret epoch=%s" % e0) == 0, "%s: no secret derived under the old epoch" % name)
        check(m1.count(r"test-send kind=\d+ scope=%s" % t.tag) == 0,
              "%s: nothing sent for the lobby: no nonce, no partial, no ack, no resend" % name)
        check(m1.count(r"start-resend") == 0, "%s: nothing resent at the start" % name)
        check(m1.count(r"sign-(begin|outcome|refused) scope=%s" % t.tag) == 0, "%s: the round is not resumed" % name)
        # The round's exposure is not left waiting (review B of #98): the person joins the lobby again (a new
        # slot, a new key pair) and then leaves it. Were the old round's exposure still unresolved, the leave
        # would be refused while its partials are "out" (409 too_late); it is Abandoned at the restart, so the
        # leave is answered 200 and the new slot closes.
        mk_j = m1.mark()
        w.join(m1, t)
        rj = m1.wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk_j)
        check(rj is not None and rj.group(1) == "200" and
              m1.wait_for(r"slot-opened scope=%s .*role=member" % t.tag, timeout=10, start=mk_r) is not None,
              "%s: the person joins the lobby again: a new slot (join answered %s)" % (name, rj.group(1) if rj else None))
        time.sleep(1)
        mk_l = m1.mark()
        m1.send(cmd(LEAVE, (12, t.scope)))
        rl = m1.wait_for(r"command-result id=\S+ status=(\d+)", timeout=10, start=mk_l)
        check(rl is not None and rl.group(1) == "200", "%s: its leave is answered 200, not too_late (got %s)"
              % (name, rl.group(1) if rl else None))
        check(m1.count(r"too_late", start=mk_l) == 0, "%s: no too_late: the old round's exposure is Abandoned" % name)
        w.clean(name)
    finally:
        kill_all(w.procs)


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(work, exist_ok=True)
    leave_held(exe, work)
    restore_mid_round(exe, work)
    return check.result("partials_hold", work)


if __name__ == "__main__":
    sys.exit(main())
