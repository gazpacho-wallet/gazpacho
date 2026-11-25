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
  4. change.gzm removed (a lost file, or a restore into a new folder): the
     start says the change chain is read wide.
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

        os.remove(mark_file())
        p = start()
        lm = p.wait_for(r"wallet-change-mark mark=(\d+) wide=(\d)")
        planned(p)
        check(lm is not None and lm.group(2) == "1", "4: with change.gzm gone the change chain is read wide (%s)"
              % (lm.group(0) if lm else None))
    finally:
        kill_all(procs)
    return check.result("program_change_mark", logs)


if __name__ == "__main__":
    sys.exit(main())
