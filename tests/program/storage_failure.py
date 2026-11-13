#!/usr/bin/env python3
"""program_storage_failure: storage and node failures, and the in-process
restart (review of PR 27: H1, M5, L6; contract v2 section 1).

    python3 -I storage_failure.py PATH_TO_GAZPACHO_TEST WORK_DIR

A host and one member at a time:
  1. The member's 3rd batch (a ping record) is written and its sync fails
     (--test-sync-fail-at). The stand-in cuts it back: the incarnation ends,
     the program starts again in process, and that ping is not in the journal
     and its reply is never resent (no "start-resend" of it). The restart
     closes every connection: the host sees the member's old connection close
     (was_connected=1) within a second, and the member comes back on a new
     connection. The member's test timer fires only under the incarnation
     that set it: the old one's never fires after the restart.
  2. The same with the cut back failing too (--test-cut-fail): the store is
     poisoned, the program exits 6 without starting again, and the next start
     refuses until storage.failed is removed.
  3. A node error (--test-node-error-at): fatal, restarted; the dead
     incarnation saves nothing after its fatal line (the journal holds no batch
     of it above the "issued" it logged).
  4. A send too big for the transport (--test-oversize-send): fatal.
"""
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, parse_journal, peer_id, ping_payloads, run  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    common = ["--no-chain", "--no-interface", "--reconnect-ms", "100", "--test-pings", "10", "--test-ping-ms", "60"]
    procs = []
    try:
        host = Proc("host", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host",
                             "--listen", "127.0.0.1:0", "--name", "host"] + common, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "host listens")
            return 1
        hkey, port = k.group(1), m.group(1)
        hp = peer_id(hkey)
        connect = ["--connect", "%s@127.0.0.1:%s" % (hkey, port)]

        # 1. a sync that fails, cut back, restarted in process -----------------
        d1 = os.path.join(work, "m1")
        m1 = Proc("m1", [exe, "--data-dir", d1, "--role", "member", "--name", "m1", "--test-sync-fail-at", "9",
                         "--test-timer-ms", "100"] + connect + common, logs)
        procs.append(m1)
        mk = m1.wait_for(r"member key=([0-9a-f]{66})")
        mp = peer_id(mk.group(1)) if mk else "?"
        f = m1.wait_for(r"save-failed .*ping-payload=([0-9a-f]+)")
        lost = bytes.fromhex(f.group(1)) if f else b"?"
        check(f is not None, "member 1's 9th batch, a ping record (%s), fails to sync" % lost.decode(errors="replace"))
        i_fatal = m1.index_of(r"fatal why=storage-failed incarnation=1")
        i_rs = m1.index_of(r"restart-from-storage after=storage-failed")
        r2 = m1.wait_for(r"ready incarnation=2 resent=(\d+)")
        check(i_fatal is not None and i_rs is not None and r2 is not None,
              "the failure is fatal and the program starts again in process (incarnation 2)")
        check(m1.find(r"start-resend peer=%s payload=%s" % (hp, lost.hex()))[0] is None,
              "the reply to the ping whose sync failed is never resent")
        check(m1.wait_for(r"pings-done peer=%s n=10" % hp) is not None, "member 1's pings are all answered")
        check(host.wait_for(r"pings-done peer=%s n=10" % mp) is not None,
              "the host's pings to member 1 are all answered after its restart (no stale connection is used)")
        m1.stop()
        j = parse_journal(os.path.join(d1, "journal.standin"))
        inc1 = [r[1][24:] for e in j if e[0] == "BTCH" and e[1] == 1 for r in e[3] if r[0] == 0x7e570001]
        check(lost not in inc1 and len(inc1) > 0,
              "incarnation 1's journal holds its other pings but not the one whose sync failed")
        # every connection closed by the restart
        t_rs = m1.times[i_rs] if i_rs is not None else 0
        closes = [(host.times[i], l) for i, l in enumerate(host.lines)
                  if "closed conn=" in l and "was_connected=1" in l and ("key=" + (mk.group(1) if mk else "?")) in l]
        conns = sorted(set(l.split("conn=")[1].split()[0] for l in host.lines
                           if " connected peer=%s " % mp in l))
        check(any(0 <= t - t_rs <= 1.0 for t, _ in closes),
              "the restart closes the member's connection: the host sees it close within 1 s")
        check(len(conns) >= 2, "the member comes back on a new connection (host conns %s)" % conns)
        # timers: the old incarnation's never fires after the restart
        late_old = [l for l in m1.lines[i_rs or 0:] if "test-timer fired incarnation=1" in l]
        check(m1.find(r"test-timer fired incarnation=1")[0] is not None and not late_old and
              m1.find(r"test-timer fired incarnation=2")[0] is not None,
              "the test timer fires in each incarnation, never the old one after the restart")

        # 2. the cut back fails too: poisoned, exit 6, refused until a person looks
        d2 = os.path.join(work, "m2")
        m2 = Proc("m2", [exe, "--data-dir", d2, "--role", "member", "--name", "m2", "--test-sync-fail-at", "3",
                         "--test-cut-fail"] + connect + common, logs)
        procs.append(m2)
        code = m2.exit_code(30)
        check(code == 6 and m2.find(r"storage poisoned")[0] is not None and
              m2.find(r"restart-from-storage")[0] is None and os.path.exists(os.path.join(d2, "storage.failed")),
              "a cut back that fails too stops the program (exit %s), no restart, storage.failed left" % code)
        code, out = run(exe, "--data-dir", d2, "--role", "member", "--name", "m2", *(connect + common))
        check(code == 4 and "storage.failed" in out, "the next start refuses (exit %s)" % code)
        os.unlink(os.path.join(d2, "storage.failed"))
        m2b = Proc("m2b", [exe, "--data-dir", d2, "--role", "member", "--name", "m2"] + connect + common, logs)
        procs.append(m2b)
        check(m2b.wait_for(r"ready incarnation=2") is not None, "once a person removes it, the folder starts again")
        m2b.stop()

        # 3. a node error: fatal, and nothing saved after it ---------------------
        # A host that pings fast, so several events wait in one turn when the
        # error comes: none of them may reach the dead incarnation's node.
        fast = Proc("fast-host", [exe, "--data-dir", os.path.join(work, "fast"), "--role", "host", "--listen",
                                  "127.0.0.1:0", "--name", "fast", "--no-chain", "--no-interface",
                                  "--test-pings", "300", "--test-ping-ms", "2"], logs)
        procs.append(fast)
        fk = fast.wait_for(r"host key=([0-9a-f]{66})")
        fm = fast.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        d3 = os.path.join(work, "m3")
        m3 = Proc("m3", [exe, "--data-dir", d3, "--role", "member", "--name", "m3", "--test-node-error-at", "40",
                         "--connect", "%s@127.0.0.1:%s" % (fk.group(1) if fk else "00", fm.group(1) if fm else "1")]
                  + common, logs)
        procs.append(m3)
        hp = peer_id(fk.group(1)) if fk else hp
        fe = m3.wait_for(r"fatal why=node-error incarnation=1 issued=(\d+)")
        check(fe is not None and m3.wait_for(r"ready incarnation=2") is not None,
              "a node error is fatal and restarted from storage")
        check(m3.wait_for(r"pings-done peer=%s n=10" % hp) is not None, "member 3 goes on after it")
        m3.stop()
        issued = int(fe.group(1)) if fe else -1
        after = [e for e in parse_journal(os.path.join(d3, "journal.standin"))
                 if e[0] == "BTCH" and e[1] == 1 and e[2] > issued]
        check(fe is not None and not after, "the dead incarnation saved nothing after its fatal line")

        # 4. a send too big for the transport -------------------------------------
        d4 = os.path.join(work, "m4")
        m4 = Proc("m4", [exe, "--data-dir", d4, "--role", "member", "--name", "m4", "--test-oversize-send", "70000"]
                  + connect + common, logs)
        procs.append(m4)
        check(m4.wait_for(r"fatal why=message-too-big") is not None, "a member message over 65,495 bytes is fatal")
        m4.p.kill()
        time.sleep(0.1)
    finally:
        kill_all(procs)
    return check.result("storage failure", logs)


if __name__ == "__main__":
    sys.exit(main())
