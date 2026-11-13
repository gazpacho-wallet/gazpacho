#!/usr/bin/env python3
"""Two-process test of the gazpacho program (stream S11).

    python3 -I two_process.py PATH_TO_GAZPACHO WORK_DIR

A host and two members, each a separate `gazpacho` process with its own data
folder, on loopback with short timers:

  1. The members connect to the host over the transport (BOLT 8). Every
     process sends placeholder pings to its peers (--test-pings), and every
     process's node answers them through its real runner and journal
     stand-in: save the ping, then send the pong.
  2. The host stops dead (--test-crash-at-ping) right after the batch holding
     one ping record is durable and before its reply could leave. Restarted on
     the same data folder, it starts from storage under incarnation 2 and its
     start resends exactly that reply; the member that sent the ping gets it.
  3. Member 1's journal fails on purpose (--test-storage-fail-at): the failure
     is fatal, and the program starts again from storage in the same process
     under a new incarnation, and goes on.
  4. Member 2 is killed (SIGKILL) mid-run and restarted on its folder: it
     comes back under incarnation 2 and finishes.
  5. Every ping of every process is answered at least once.
  6. A second program on a folder in use is refused (the lock); a folder of
     one role is refused for another; mainnet is refused before any folder is
     made; SIGTERM stops each process cleanly.

Standard library only. Exits 0 if every check passes.
"""
import hashlib
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

PINGS = 40
PING_MS = 40
CRASH_AT = 15        # the host stops after its 15th durable ping record
FAIL_AT = 6          # member 1's 6th journal append fails
TIMEOUT = 60.0

failures = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what, flush=True)
    if not cond:
        failures.append(what)


def peer_id(key_hex):
    return hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:16]


class Proc:
    def __init__(self, name, args, log_dir):
        self.name = name
        self.lines = []
        self.cv = threading.Condition()
        self.log = open(os.path.join(log_dir, name + ".log"), "a")
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            line = line.rstrip("\n")
            self.log.write(line + "\n")
            self.log.flush()
            with self.cv:
                self.lines.append(line)
                self.cv.notify_all()
        with self.cv:
            self.cv.notify_all()

    def wait_for(self, pattern, timeout=TIMEOUT, start=0):
        """The first match of `pattern` at or after line `start`, or None."""
        rx = re.compile(pattern)
        end = time.time() + timeout
        with self.cv:
            i = start
            while True:
                while i < len(self.lines):
                    m = rx.search(self.lines[i])
                    if m:
                        return m
                    i += 1
                left = end - time.time()
                if left <= 0 or (self.p.poll() is not None and i >= len(self.lines)):
                    # one last look after the reader drained the pipe
                    if self.p.poll() is not None:
                        time.sleep(0.1)
                        while i < len(self.lines):
                            m = rx.search(self.lines[i])
                            if m:
                                return m
                            i += 1
                    return None
                self.cv.wait(min(left, 0.2))

    def count(self, pattern, start=0):
        rx = re.compile(pattern)
        with self.cv:
            return sum(1 for l in self.lines[start:] if rx.search(l))

    def mark(self):
        with self.cv:
            return len(self.lines)

    def exit_code(self, timeout=TIMEOUT):
        try:
            return self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None


def run(exe, *args):
    r = subprocess.run([exe] + list(args), capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    exe, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    logs = os.path.join(work, "logs")
    os.makedirs(logs)
    hdir, m1dir, m2dir = (os.path.join(work, n) for n in ("host", "m1", "m2"))
    common = ["--no-chain", "--no-interface", "--handshake-ms", "3000", "--recv-ms", "3000",
              "--send-ms", "3000", "--reconnect-ms", "100",
              "--test-pings", str(PINGS), "--test-ping-ms", str(PING_MS)]
    procs = []
    try:
        # --- mainnet refused before anything is made --------------------------
        code, out = run(exe, "--data-dir", os.path.join(work, "never"), "--role", "host",
                        "--no-chain", "--network", "mainnet")
        check(code == 2 and "mainnet" in out and not os.path.exists(os.path.join(work, "never")),
              "mainnet is refused and no data folder is made (exit %s)" % code)

        # --- the host ---------------------------------------------------------
        host = Proc("host-1", [exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:0",
                               "--name", "host", "--test-crash-at-ping", str(CRASH_AT)] + common, logs)
        procs.append(host)
        m = host.wait_for(r"listening address=127\.0\.0\.1:(\d+) key=([0-9a-f]{66})")
        check(m is not None, "host listens")
        if not m:
            return 1
        port, hkey = m.group(1), m.group(2)
        check(host.wait_for(r"ready incarnation=1 resent=0") is not None, "host starts under incarnation 1")

        # one program per data folder
        code, out = run(exe, "--data-dir", hdir, "--role", "host", "--listen", "127.0.0.1:0", "--no-chain")
        check(code == 3 and "in use" in out, "a second program on the host's folder is refused (exit %s)" % code)

        connect = ["--connect", "%s@127.0.0.1:%s" % (hkey, port)]
        m1 = Proc("m1-1", [exe, "--data-dir", m1dir, "--role", "member", "--name", "m1",
                           "--test-storage-fail-at", str(FAIL_AT)] + connect + common, logs)
        m2 = Proc("m2-1", [exe, "--data-dir", m2dir, "--role", "member", "--name", "m2"] + connect + common, logs)
        procs += [m1, m2]
        keys = {}
        for mp, n in ((m1, "m1"), (m2, "m2")):
            mm = mp.wait_for(r"member key=([0-9a-f]{66}) host-peer=([0-9a-f]{16})")
            check(mm is not None and mm.group(2) == peer_id(hkey), "%s names the host by its key" % n)
            keys[n] = mm.group(1) if mm else ""
        check(host.wait_for(r"connected peer=%s" % peer_id(keys["m1"])) is not None and
              host.wait_for(r"connected peer=%s" % peer_id(keys["m2"])) is not None,
              "both members connect to the host over BOLT 8")

        # --- the host stops dead after a ping is durable ----------------------
        c = host.wait_for(r"test-crash ping-durable peer=([0-9a-f]{16}) payload=([0-9a-f]+)")
        check(c is not None, "the host stops after the %dth ping record is durable" % CRASH_AT)
        check(host.exit_code() == 70, "the host's crash exit status is the test hook's")
        crash_peer, crash_payload = (c.group(1), bytes.fromhex(c.group(2)).decode()) if c else ("", "")
        print("     the reply cut off was to %s for ping %s" % (crash_peer, crash_payload), flush=True)

        # Restart on the same folder and port (the old socket may linger).
        host2 = None
        for _ in range(40):
            host2 = Proc("host-2", [exe, "--data-dir", hdir, "--role", "host",
                                    "--listen", "127.0.0.1:" + port, "--name", "host"] + common, logs)
            if host2.wait_for(r"listening address", timeout=5) is not None:
                break
            host2.exit_code(5)
            time.sleep(0.25)
        procs.append(host2)
        r = host2.wait_for(r"ready incarnation=(\d+) resent=(\d+)")
        check(r is not None and r.group(1) == "2" and int(r.group(2)) >= 1,
              "the restarted host starts from storage under incarnation 2 and resends (resent=%s)"
              % (r.group(2) if r else "?"))
        resend = host2.wait_for(r"start-resend peer=%s payload=%s" %
                                (crash_peer, crash_payload.encode().hex()), timeout=1)
        check(resend is not None, "its start resends the reply that never left before the crash")
        # The member whose ping it was receives that reply.
        who = "m1" if crash_peer == peer_id(keys["m1"]) else "m2"
        mp = m1 if who == "m1" else m2
        k = crash_payload.split("/")[-1]
        check(crash_payload.startswith(who + "/") and
              mp.wait_for(r"pong peer=%s k=%s " % (peer_id(hkey), k)) is not None,
              "%s receives the pong for %s" % (who, crash_payload))

        # --- member 1's storage failure: fatal, restarted from storage --------
        f = m1.wait_for(r"fatal why=storage-failed incarnation=1")
        check(f is not None, "member 1's journal failure is fatal for its incarnation")
        check(m1.wait_for(r"restart-from-storage after=storage-failed") is not None and
              m1.wait_for(r"ready incarnation=2") is not None,
              "member 1 starts again from storage in the same process, under incarnation 2")

        # --- member 2 is killed mid-run and restarted --------------------------
        mark = m2.mark()
        check(m2.wait_for(r"pong peer=", start=mark) is not None, "member 2 is running when it is killed")
        m2.p.send_signal(signal.SIGKILL)
        m2.exit_code()
        m2b = Proc("m2-2", [exe, "--data-dir", m2dir, "--role", "member", "--name", "m2"] + connect + common, logs)
        procs.append(m2b)
        check(m2b.wait_for(r"ready incarnation=2") is not None, "member 2 restarts under incarnation 2")

        # --- every ping answered ----------------------------------------------
        hp = peer_id(hkey)
        check(m1.wait_for(r"pings-done peer=%s n=%d" % (hp, PINGS)) is not None,
              "member 1: all %d pings to the host answered" % PINGS)
        check(m2b.wait_for(r"pings-done peer=%s n=%d" % (hp, PINGS)) is not None,
              "member 2 (restarted): all %d pings to the host answered" % PINGS)
        for n in ("m1", "m2"):
            check(host2.wait_for(r"pings-done peer=%s n=%d" % (peer_id(keys[n]), PINGS)) is not None,
                  "host: all %d pings to %s answered by %s's node" % (PINGS, n, n))

        # --- clean stop ---------------------------------------------------------
        for p in (host2, m1, m2b):
            p.p.send_signal(signal.SIGTERM)
        for p in (host2, m1, m2b):
            check(p.exit_code() == 0 and p.wait_for(r"stopped status=0", timeout=2) is not None,
                  "%s stops cleanly on SIGTERM" % p.name)

        # one role per folder, and the folder is free again after a stop
        code, out = run(exe, "--data-dir", hdir, "--role", "member", "--no-chain",
                        "--connect", "%s@127.0.0.1:%s" % (hkey, port))
        check(code == 4 and "belongs to a host" in out, "the host's folder is refused as a member's (exit %s)" % code)
    finally:
        for p in procs:
            if p and p.p.poll() is None:
                p.p.kill()
    if failures:
        print("FAIL: %d check(s); logs in %s" % (len(failures), logs))
        return 1
    print("PASS: two-process test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
