#!/usr/bin/env python3
"""program_restart_policy: when the program stops restarting (review of PR 27,
M6; review B, B2: mutants B48 and B49).

    python3 -I restart_policy.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. The restart window: a member whose node fails on the first event of
     every incarnation (--test-node-error-at 1 --test-node-error-always)
     restarts from storage five times and then stops, exit 1, within seconds:
     six incarnations, five restarts, never more.
  2. A stop during a restart: a member whose node fails once, with a SIGTERM
     arriving while that incarnation ends (--test-stop-at-restart), stops
     without a new start: exit 0, one start counter, one incarnation in its
     journal.
"""
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, parse_journal  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    base = ["--no-chain", "--no-interface", "--reconnect-ms", "50", "--handshake-ms", "3000"]
    procs = []
    try:
        host = Proc("host", [exe, "--data-dir", os.path.join(work, "host"), "--role", "host", "--listen",
                             "127.0.0.1:0", "--name", "host", "--max-per-address", "0"] + base, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "the host listens")
            return 1
        connect = ["--connect", "%s@127.0.0.1:%s" % (k.group(1), m.group(1))]

        # 1. the restart window -------------------------------------------------
        bad = Proc("always", [exe, "--data-dir", os.path.join(work, "always"), "--role", "member", "--name",
                              "always", "--test-node-error-at", "1", "--test-node-error-always"] + connect + base,
                   logs)
        procs.append(bad)
        code = bad.exit_code(60)
        restarts = bad.count(r"restart-from-storage")
        counters = [int(x.group(1)) for x in (re.search(r"start-counter state=\S+ incarnation=(\d+)", l)
                                               for l in bad.lines) if x]
        check(code == 1 and bad.find(r"stopping after 6 restarts within 10 minutes")[0] is not None,
              "a node that fails at every start stops the program, exit 1 (exit %s)" % code)
        check(restarts == 5 and counters == [1, 2, 3, 4, 5, 6],
              "after exactly five restarts in process: incarnations %s, %d restarts" % (counters, restarts))

        # 2. a stop during a restart --------------------------------------------
        sd = os.path.join(work, "stop")
        st = Proc("stop", [exe, "--data-dir", sd, "--role", "member", "--name", "stop", "--test-node-error-at", "1",
                           "--test-stop-at-restart"] + connect + base, logs)
        procs.append(st)
        code = st.exit_code(30)
        check(st.find(r"fatal why=node-error incarnation=1")[0] is not None and
              st.find(r"stop during restart: no new start")[0] is not None and code == 0,
              "a stop that arrives while an incarnation ends stops the program (exit %s)" % code)
        incs = [e[1] for e in parse_journal(os.path.join(sd, "journal.standin")) if e[0] == "INCN"]
        check(st.count(r"start-counter ") == 1 and st.count(r"ready incarnation=") == 1 and incs == [1],
              "no new start after it: one start counter, one incarnation in the journal (%s)" % incs)
        host.stop()
    finally:
        kill_all(procs)
    return check.result("restart policy", logs)


if __name__ == "__main__":
    sys.exit(main())
