#!/usr/bin/env python3
"""T12 (second half), program_release_build (contract-v2.md section 12).

    python3 -I release_build.py PATH_TO_GAZPACHO PATH_TO_GAZPACHO_TEST WORK_DIR

The release `gazpacho`:
  - its symbols hold no seeded random source (the simulator's sim_rng_*), no
    test traffic (gzp_testping_*) and no test-kind code;
  - it refuses every --test-* option;
  - kind 32767 is never delivered: a test-build member's pings to a release
    host stay unanswered while the connection stays up.
Needs `nm` (binutils).
"""
import os
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, kill_all, parse_journal, peer_id, ping_payloads, run  # noqa: E402

check = Checks()
FORBIDDEN = re.compile(r"sim_rng|sim_chacha|gzp_testping|gzp_standin_fail_at|gzp_standin_put_restore|gzp_standin_test_hooks")
# Each name the release check looks for, and that the test build does have, so
# that each half of the check can fail (review of PR 27, M5).
IN_TEST = ("gzp_testping", "gzp_standin_fail_at", "gzp_standin_put_restore", "gzp_standin_test_hooks")
TEST_STRINGS = (b"--test-pings", b"--test-timer-ms", b"--test-start-delay-ms", b"--test-node-error-at",
                b"tests only (gazpacho-test)", b"test-timer fired", b"payload=%s", b"ping-payload")


def symbols(path):
    r = subprocess.run(["nm", "-C", path], capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(["nm", "-D", path], capture_output=True, text=True)
    return [l.split()[-1] for l in r.stdout.splitlines() if l.strip()]


def main():
    rel, tst, work = (os.path.abspath(a) for a in sys.argv[1:4])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    procs = []
    try:
        rs, ts = symbols(rel), symbols(tst)
        bad = sorted(s for s in rs if FORBIDDEN.search(s))
        check(len(rs) > 100 and not bad, "the release binary names no seeded source and no test code %s" % bad[:5])
        missing = [n for n in IN_TEST if not any(n in s for s in ts)]
        check(not missing, "the check would see them: the test build has each of %s (missing %s)" % (IN_TEST, missing))
        # Review B of PR 27 (B4, B6): not even the names of the test options,
        # their usage lines, the test timer's line, or a format that prints
        # message bytes. Each is in the test build, so each half can fail.
        with open(rel, "rb") as f:
            relb = f.read()
        with open(tst, "rb") as f:
            tstb = f.read()
        leaked = [n.decode() for n in TEST_STRINGS if n in relb]
        check(not leaked, "the release binary holds no test option name, test usage line, test-timer line or "
                          "payload format %s" % leaked)
        unseen = [n.decode() for n in TEST_STRINGS if n not in tstb]
        check(not unseen, "the check would see them: the test build has each (missing %s)" % unseen)
        code, out = run(rel, "--data-dir", os.path.join(work, "x"), "--role", "host", "--no-chain",
                        "--test-pings", "1")
        check(code == 2 and "only in the test build" in out and not os.path.exists(os.path.join(work, "x")),
              "the release build refuses --test-* (exit %s)" % code)

        host = Proc("release-host", [rel, "--data-dir", os.path.join(work, "host"), "--role", "host",
                                     "--listen", "127.0.0.1:0", "--no-chain", "--no-interface"], logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "the release host listens")
            return 1
        mem = Proc("test-member", [tst, "--data-dir", os.path.join(work, "m"), "--role", "member", "--name", "m",
                                   "--no-chain", "--no-interface", "--reconnect-ms", "100",
                                   "--connect", "%s@127.0.0.1:%s" % (k.group(1), m.group(1)),
                                   "--test-pings", "5", "--test-ping-ms", "50"], logs)
        procs.append(mem)
        check(mem.wait_for(r"connected peer=%s" % peer_id(k.group(1))) is not None,
              "a test-build member connects to the release host")
        time.sleep(2)
        check(mem.count(r"disconnected") == 0 and host.count(r"disconnected") == 0,
              "the connection stays up (an unknown odd kind is ignored)")
        host.stop()
        pings = ping_payloads(parse_journal(os.path.join(work, "host", "journal.standin")))
        # Delivery would leave a ping record: the release adapter extracts
        # record 1 of kind 32767 like the test build's, and its node saves it.
        check(mem.count(r"pong peer=") == 0 and not pings,
              "its kind-32767 pings never reach the release node (no ping record in its journal)")

    finally:
        kill_all(procs)
    return check.result("release build", logs)


if __name__ == "__main__":
    sys.exit(main())
