#!/usr/bin/env python3
"""program_loop_liveness: the one loop stays responsive (review of PR 27:
M1, M4, M5, L6).

    python3 -I liveness.py PATH_TO_GAZPACHO_TEST WORK_DIR

  1. Flood: a member pings the host every millisecond (20,000 pings, so at least 20 s) while the
     host has a 100 ms test timer and its own pings every 50 ms. The host's
     timer keeps firing (no gap over 1 s), its own pings are answered during
     the flood, and a SIGTERM 3 s in stops it within 1 s.
  2. An idle program's poll timeout honours its timers: a 200 ms test timer
     fires about ten times in 2 s with nothing else to wake the loop.
  3. Listening only after the start, seen from outside: a TCP connect to the
     host's port is refused for the whole of a start held 2 s; when one is
     first accepted, "ready" has been written.
  4. SIGPIPE: the reader of the host's standard output goes away; the host
     carries on and stops cleanly on SIGTERM.
"""
import os
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gzp_harness import Checks, Proc, can_connect, free_port, kill_all, parse_journal, peer_id  # noqa: E402

check = Checks()


def main():
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    base = ["--no-chain", "--no-interface", "--reconnect-ms", "100"]
    procs = []
    try:
        # 1. flood -----------------------------------------------------------------
        host = Proc("flood-host", [exe, "--data-dir", os.path.join(work, "fh"), "--role", "host", "--listen",
                                   "127.0.0.1:0", "--name", "host", "--test-timer-ms", "100",
                                   "--test-pings", "1000", "--test-ping-ms", "50"] + base, logs)
        procs.append(host)
        k = host.wait_for(r"host key=([0-9a-f]{66})")
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+)")
        if not (k and m):
            check(False, "host listens")
            return 1
        hkey, port = k.group(1), m.group(1)
        mem = Proc("flood-member", [exe, "--data-dir", os.path.join(work, "fm"), "--role", "member", "--name", "m",
                                    "--connect", "%s@127.0.0.1:%s" % (hkey, port), "--test-pings", "20000",
                                    "--test-ping-ms", "1"] + base, logs)
        procs.append(mem)
        mk = mem.wait_for(r"member key=([0-9a-f]{66})")
        check(mem.wait_for(r"connected peer=%s" % peer_id(hkey)) is not None, "the member connects")
        t_flood = time.time()
        time.sleep(3.0)
        mark_host = host.mark()
        flood_on = mem.count(r"pong peer=") < 20000
        host.p.send_signal(signal.SIGTERM)
        t_term = time.time()
        code = host.exit_code(30)
        took = time.time() - t_term
        check(flood_on, "the member was still flooding when the host was stopped")
        check(code == 0 and took < 1.0, "SIGTERM during the flood stops the host within 1 s (%.2f s)" % took)
        fires = [host.times[i] for i, l in enumerate(host.lines[:mark_host]) if "test-timer fired" in l
                 and host.times[i] >= t_flood]
        gaps = [b - a for a, b in zip(fires, fires[1:])]
        check(len(fires) >= 3 and (max(gaps) if gaps else 9) < 2.0,
              "the host's 100 ms timer kept firing during the flood (%d fires, largest gap %.2f s)"
              % (len(fires), max(gaps) if gaps else -1))
        mem.stop()
        # The host's own pings went out during the flood: the member's node
        # saved them (their answers wait behind the flood in the connection's
        # order, which is right).
        got = [r[1][82:] for e in parse_journal(os.path.join(work, "fm", "journal.standin")) if e[0] == "BTCH"
               for r in e[3] if r[0] == 0x7e570001 and r[1][82:].startswith(b"host/")]
        check(len(got) >= 5, "the host's own pings kept going out during the flood (%d reached the member)" % len(got))

        # 2. an idle loop's poll timeout honours timers ----------------------------
        idle = Proc("idle", [exe, "--data-dir", os.path.join(work, "idle"), "--role", "host", "--listen",
                             "127.0.0.1:0", "--name", "idle", "--test-timer-ms", "200"] + base, logs)
        procs.append(idle)
        r = idle.wait_for(r"ready incarnation=1")
        time.sleep(2.1)
        n = idle.count(r"test-timer fired")
        check(r is not None and 8 <= n <= 12, "an idle program's 200 ms timer fires about ten times in 2 s (%d)" % n)
        idle.stop()

        # 3. listen only after the start, seen from outside -------------------------
        p3 = free_port()
        late = Proc("late-listen", [exe, "--data-dir", os.path.join(work, "late"), "--role", "host", "--listen",
                                    "127.0.0.1:%d" % p3, "--name", "late", "--test-start-delay-ms", "2000"] + base,
                    logs)
        procs.append(late)
        check(late.wait_for(r"start-delay ms=2000") is not None, "a host holds its start 2 s")
        # Wait for the listener itself (a connect that succeeds), not for the
        # "ready" line: the program writes "ready" and then listens, so when a
        # connect first succeeds, "ready" is already in the pipe, however far
        # behind this test's reader is (review B of PR 27, B3: reading the
        # line first raced with the reader thread).
        t_held = time.time()
        refused, t_open = 0, None
        while late.p.poll() is None and time.time() < t_held + 30:
            if can_connect(p3):
                t_open = time.time()
                break
            refused += 1
            time.sleep(0.1)
        ready_seen = late.wait_for(r"ready incarnation", timeout=5.0) is not None
        check(t_open is not None and refused >= 5 and t_open - t_held >= 1.0 and ready_seen,
              "connects are refused until the start is over: %d refused, the first accepted %.2f s into a "
              "2 s held start, \"ready\" already written then (%s)"
              % (refused, (t_open or 0) - t_held, ready_seen))
        late.stop()

        # 4. SIGPIPE on standard output ---------------------------------------------
        p = subprocess.Popen([exe, "--data-dir", os.path.join(work, "pipe"), "--role", "host", "--listen",
                              "127.0.0.1:0", "--name", "pipe", "--test-timer-ms", "20"] + base,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        while True:
            line = p.stdout.readline()
            if not line or b"ready incarnation" in line:
                break
        p.stdout.close()          # the reader goes away; the timer keeps writing lines
        time.sleep(1.0)
        alive = p.poll() is None
        p.send_signal(signal.SIGTERM)
        try:
            code = p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()
            code = None
        check(alive and code == 0, "with its reader gone the host lives on and stops cleanly (exit %s)" % code)
    finally:
        kill_all(procs)
    return check.result("loop liveness", logs)


if __name__ == "__main__":
    sys.exit(main())
