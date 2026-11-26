#!/usr/bin/env python3
"""program_change_mark (follow-ups of the review of PR 91): the host's change
mark, change.gzm, end to end, each start a separate gazpacho-test process
over one sealed wallet folder, no chain (the test build's invented coin).

    python3 -I change_mark.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. A new wallet: set-up keeps mark 0, so its first start is not wide; one
     plan takes change index 0.
  2. A restart: the next plan takes index 1, not 0 again.
  3. A power cut once the mark is kept and before the plan is used (the
     storage model puts back what a disk keeps, then SIGKILL): no plan is
     printed; the restart's plan takes the index after the one handed out
     before the cut, never that one again.
  4. A power cut at every storage call of a start that plans: the mark is
     the old one or the new one, opens, and the next start plans from it.
  5. A change.gzm that does not open (a flipped bit; starts.gzs copied over
     it): the host starts, reads the change chain wide, says so, plans nothing.
  6. change.gzm removed: wide, no plan; and the next start is wide again (the
     pending read is kept until a read finishes).
"""
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, free_port, kill_all  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    folder = os.path.join(work, "host")
    procs, runs = [], [0]

    def start(*extra):
        runs[0] += 1
        p = Proc("host-%d" % runs[0], [exe, "--data-dir", folder, "--role", "host", "--name", "h",
                                       "--listen", "127.0.0.1:%d" % free_port(), "--no-chain", "--no-interface",
                                       "--test-plan-once", "100000"] + list(extra), logs)
        procs.append(p)
        return p

    def planned(p):
        m = p.wait_for(r"test-plan ok=(\d) change=(\d+) mark=(\d+)")
        code = p.exit_code(timeout=30)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None, code

    def mark_file():
        for root, _, files in os.walk(folder):
            if "change.gzm" in files:
                return os.path.join(root, "change.gzm")
        return None

    try:
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        r, code = planned(p)
        check(lm is not None and lm.group(1) == "0" and lm.group(2) == "0",
              "1: a new wallet's first start: mark 0, not wide (%s)" % (lm.group(0) if lm else None))
        check(r == (1, 0, 1) and code == 0, "1: the first plan takes change index 0, the mark kept at 1 (%s, %s)"
              % (r, code))
        check(mark_file() is not None, "1: change.gzm is in the wallet's folder")

        p = start()
        r, code = planned(p)
        check(r == (1, 1, 2) and code == 0, "2: after a restart the plan takes index 1 (%s, %s)" % (r, code))

        p = start("--test-cut-after-mark")
        cut = p.wait_for(r"test-cut after=change-mark mark=(\d+)")
        code = p.exit_code(timeout=30)
        check(cut is not None and cut.group(1) == "3", "3: the cut comes once mark 3 is kept (%s)"
              % (cut.group(0) if cut else None))
        check(p.find(r"test-plan ")[1] is None and code not in (0, None), "3: killed before the plan was used (exit %s)"
              % code)
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        r, code = planned(p)
        check(lm is not None and lm.group(1) == "3", "3: the restart reads mark 3 (%s)" % (lm.group(0) if lm else None))
        check(r == (1, 3, 4) and code == 0,
              "3: the restart's plan takes index 3: index 2, handed out before the cut, is not used again (%s, %s)"
              % (r, code))

        # 4. A power cut at every storage call of a start that plans (L-5, review
        #    B of PR 93): each cut leaves the old mark or the new one, a file that
        #    opens, and no plan printed; the next start plans from that mark.
        m, k, done, iters = 4, 1, False, 0
        while k <= 80 and not done:
            p = start("--test-power-cut-at", str(k))
            r, code = planned(p)
            if r is not None:
                done = r[0] == 1 and r[1] == m
                check(done, "4: past every cut the plan takes index %d (%s)" % (m, r))
                m = r[1] + 1
                break
            check(code not in (0, None) and p.find(r"test-plan ")[1] is None,
                  "4: cut at %d: no plan printed (exit %s)" % (k, code))
            p = start()
            lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
            r, code = planned(p)
            ok = (lm is not None and lm.group(2) == "0" and int(lm.group(1)) in (m, m + 1) and r is not None
                  and r[0] == 1 and r[1] == int(lm.group(1)))
            check(ok, "4: after the cut at %d the mark is %d or %d and opens, and the plan takes it (%s, %s)"
                  % (k, m, m + 1, lm.group(0) if lm else None, r))
            if not ok:
                break
            m = r[1] + 1
            k += 1
            iters += 1
        check(done and iters > 0, "4: the sweep ends with a start no cut reaches (%d cuts)" % iters)

        # 5. A change.gzm that does not open (M-2): one bit flipped, then the start
        #    counter copied over it. The host starts, reads the change chain wide,
        #    says so, and plans nothing until that read is done.
        path = mark_file()
        with open(path, "r+b") as fh:
            data = bytearray(fh.read())
            data[60] ^= 1
            fh.seek(0)
            fh.write(bytes(data))
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        r, code = planned(p)
        check(lm is not None and lm.group(2) == "2" and p.find(r"wallet-change-mark-not-opened")[1] is not None,
              "5: a flipped bit: read as missing, wide, and told (%s)" % (lm.group(0) if lm else None))
        check(r is not None and r[0] == 0 and code == 0, "5: the host starts and plans nothing yet (%s, %s)"
              % (r, code))
        starts = None
        for root, _, files in os.walk(folder):
            if "starts.gzs" in files:
                starts = os.path.join(root, "starts.gzs")
        shutil.copyfile(starts, path)
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        r, code = planned(p)
        check(lm is not None and lm.group(2) == "2", "5: starts.gzs copied over it: the same (%s)"
              % (lm.group(0) if lm else None))
        check(r is not None and r[0] == 0 and code == 0, "5: and the host starts (%s, %s)" % (r, code))

        # 6. change.gzm removed: wide; and the pending read is kept (M-1): the
        #    next start is wide again, though no read was finished.
        os.remove(mark_file())
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        r, code = planned(p)
        check(lm is not None and lm.group(2) == "1", "6: with change.gzm gone the change chain is read wide (%s)"
              % (lm.group(0) if lm else None))
        check(r is not None and r[0] == 0, "6: no plan while that read is pending (%s)" % (r,))
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        planned(p)
        check(lm is not None and lm.group(2) == "1", "6: the next start is still wide (%s)"
              % (lm.group(0) if lm else None))
    finally:
        kill_all(procs)
    return check.result("program_change_mark", logs)


if __name__ == "__main__":
    sys.exit(main())
