#!/usr/bin/env python3
"""program_refusals: smaller rules each with a check that can fail (review B
of PR 27, B7: mutants B30, B31, B33, B35 and B37).

    python3 -I refusals.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Mainnet is refused by the parser first, whatever else is wrong: the
     message is "refusing to run on mainnet" even with no folder or role.
  2. A host given --connect is refused.
  3. A data folder open to others is refused (exit 4), and so is a key file
     open to others.
  4. The member's reconnect delay goes back to the first one after a
     connection succeeds: with the host down for a while the delay grows to
     seconds; once connected, a dropped connection (the host restarting in
     process) is followed by a reconnect within 1.5 s.
"""
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, free_port, kill_all, peer_id, run  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    base = ["--no-chain", "--no-interface"]
    procs = []
    try:
        # 1. mainnet first --------------------------------------------------------
        code, out = run(exe, "--network", "mainnet")
        check(code == 2 and "refusing to run on mainnet" in out,
              "--network mainnet alone is answered with the mainnet refusal (exit %s)" % code)

        # 2. a host with --connect ------------------------------------------------
        code, out = run(exe, "--data-dir", os.path.join(work, "hc"), "--role", "host", "--connect",
                        "02" + "11" * 32 + "@127.0.0.1:9", *base)
        check(code == 2 and "--connect is for a member" in out, "a host given --connect is refused (exit %s)" % code)

        # 3. folders and key files open to others ---------------------------------
        od = os.path.join(work, "open")
        os.makedirs(od)
        os.chmod(od, 0o755)
        code, out = run(exe, "--data-dir", od, "--role", "host", "--listen", "127.0.0.1:0", *base)
        check(code == 4 and "closed to others" in out, "a data folder open to others is refused (exit %s)" % code)
        kd = os.path.join(work, "key")
        p = Proc("key-1", [exe, "--data-dir", kd, "--role", "host", "--listen", "127.0.0.1:0", "--name", "key"] + base,
                 logs)
        procs.append(p)
        check(p.wait_for(r"ready incarnation=1") is not None and p.stop() == 0, "a fresh host starts and stops")
        os.chmod(os.path.join(kd, "transport.key"), 0o644)
        code, out = run(exe, "--data-dir", kd, "--role", "host", "--listen", "127.0.0.1:0", *base)
        check(code == 4 and "chmod 600" in out, "a key file open to others is refused (exit %s)" % code)

        # 4. the reconnect delay is reset by a success ----------------------------
        port = free_port()
        hd = os.path.join(work, "host")
        h0 = Proc("host-0", [exe, "--data-dir", hd, "--role", "host", "--listen", "127.0.0.1:%d" % port,
                             "--name", "host"] + base, logs)
        procs.append(h0)
        k = h0.wait_for(r"host key=([0-9a-f]{66})")
        h0.wait_for(r"listening address")
        h0.stop()
        hkey = k.group(1) if k else "00"
        mem = Proc("member", [exe, "--data-dir", os.path.join(work, "m"), "--role", "member", "--name", "m",
                              "--reconnect-ms", "100", "--handshake-ms", "2000",
                              "--connect", "%s@127.0.0.1:%d" % (hkey, port)] + base, logs)
        procs.append(mem)
        # 100, 200, 400, 800, 1600 ms: six failed attempts take about 3 s
        end = time.time() + 30
        while time.time() < end and mem.count(r"connect-failed|closed conn=\d+ why=\S+ was_connected=0") < 6:
            time.sleep(0.1)
        fails = mem.count(r"connect-failed|closed conn=\d+ why=\S+ was_connected=0")
        check(fails >= 6, "with the host down the member keeps trying, its delay growing (%d attempts)" % fails)
        # The host's node fails on its first event, the member's connected: the
        # host restarts in process (closing the connection, listening again
        # within milliseconds), so the member's next delay is what it shows.
        h1 = Proc("host-1", [exe, "--data-dir", hd, "--role", "host", "--listen", "127.0.0.1:%d" % port,
                             "--name", "host", "--test-node-error-at", "1"] + base, logs)
        procs.append(h1)
        hp = peer_id(hkey)
        i_c1 = mem.index_of(r" connected peer=%s" % hp, timeout=15)
        check(i_c1 is not None, "the member connects once the host is back")
        i_d = mem.index_of(r" disconnected peer=%s" % hp, timeout=15, start=(i_c1 or 0) + 1)
        i_c2 = mem.index_of(r" connected peer=%s" % hp, timeout=15, start=(i_d or 0) + 1)
        took = mem.times[i_c2] - mem.times[i_d] if i_d is not None and i_c2 is not None else 99
        check(h1.find(r"restart-from-storage")[0] is not None and took < 1.5,
              "after a success the delay is back to 100 ms: reconnected %.2f s after the host dropped it" % took)
        h1.stop()
        mem.stop()
    finally:
        kill_all(procs)
    return check.result("refusals and reconnect", logs)


if __name__ == "__main__":
    sys.exit(main())
