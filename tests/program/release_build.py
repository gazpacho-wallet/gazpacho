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
from gzp_harness import Checks, Proc, kill_all, peer_id, run  # noqa: E402

check = Checks()
FORBIDDEN = re.compile(r"sim_rng|sim_chacha|gzp_testping|test_kind|GZ_ENV_KIND_TEST", re.IGNORECASE)


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
        check(any("gzp_testping" in s for s in ts), "the check would see them: the test build has gzp_testping_*")
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
        check(mem.count(r"pong peer=") == 0 and host.count(r"pings-done|pong ") == 0,
              "its kind-32767 pings are never delivered to the release node")
        check(mem.count(r"disconnected") == 0 and host.count(r"disconnected") == 0,
              "and the connection stays up (an unknown odd kind is ignored)")
    finally:
        kill_all(procs)
    return check.result("release build", logs)


if __name__ == "__main__":
    sys.exit(main())
