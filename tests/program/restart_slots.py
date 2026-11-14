#!/usr/bin/env python3
"""program_restart_slots (written by review B of PR 27, copied as written): after an in-process restart of the host, a member that was
down at the restart comes back on a new connection and is answered (stale
connection slots, M45). usage: slots_t.py GAZPACHO_TEST WORKDIR [ignored]"""
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

EXE, WORK = sys.argv[1], sys.argv[2]
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK)
COMMON = ["--no-chain", "--no-interface", "--handshake-ms", "2000", "--ping-ms", "400", "--pong-ms", "800",
          "--recv-ms", "3000", "--send-ms", "2000"]
fails = []


def check(c, what):
    print(("ok   " if c else "FAIL ") + what, flush=True)
    if not c:
        fails.append(what)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class P:
    def __init__(self, name, args):
        self.lines, self.cv = [], threading.Condition()
        d = os.path.join(WORK, name)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        self.p = subprocess.Popen([EXE, "--data-dir", d, "--name", name] + COMMON + args,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        log = open(os.path.join(WORK, name + ".log"), "a")

        def rd():
            for l in self.p.stdout:
                log.write(l)
                log.flush()
                with self.cv:
                    self.lines.append(l.rstrip("\n"))
                    self.cv.notify_all()
        threading.Thread(target=rd, daemon=True).start()

    def wait(self, rx, timeout=20):
        r = re.compile(rx)
        end = time.time() + timeout
        with self.cv:
            while time.time() < end:
                for l in self.lines:
                    if r.search(l):
                        return l
                self.cv.wait(0.2)
        return None

    def count(self, rx):
        r = re.compile(rx)
        with self.cv:
            return sum(1 for l in self.lines if r.search(l))

    def term(self):
        if self.p.poll() is None:
            self.p.terminate()
        try:
            return self.p.wait(15)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None


port = free_port()
h = P("host0", ["--role", "host", "--listen", "127.0.0.1:%d" % port])
h.wait(r"host key=")
h.term()
shutil.rmtree(os.path.join(WORK, "host"), ignore_errors=True)
shutil.copytree(os.path.join(WORK, "host0"), os.path.join(WORK, "host"))
os.chmod(os.path.join(WORK, "host"), 0o700)
key = re.search(r"key=([0-9a-f]{66})", open(os.path.join(WORK, "host0.log")).read()).group(1)
# Events 1 and 2 are the members' connections, event 3 a message: a node error
# there restarts the host in process with both members connected.
h = P("host", ["--role", "host", "--listen", "127.0.0.1:%d" % port, "--test-pings", "5", "--test-ping-ms", "50",
               "--test-node-error-at", "3"])
h.wait(r"listening", 10)
mk = lambda n: P(n, ["--role", "member", "--connect", "%s@127.0.0.1:%d" % (key, port), "--reconnect-ms", "1500",
                     "--test-pings", "5", "--test-ping-ms", "300"])
m1 = mk("m1")
time.sleep(0.05)
m2 = mk("m2")
check(h.wait(r"restart-from-storage", 15) is not None, "the host restarts in process with both members connected")
h.wait(r"ready incarnation=2 ", 10)
# take the new transport's first connection numbers before the members come back
raw = []
for _ in range(3):
    try:
        raw.append(socket.create_connection(("127.0.0.1", port), timeout=1))
    except OSError:
        pass
time.sleep(0.3)
for s in raw:
    s.close()
check(m1.wait(r"pings-done", 20) is not None, "m1 gets every pong after the restart")
check(m2.wait(r"pings-done", 20) is not None, "m2 gets every pong after the restart")
check(h.count(r"pings-done") >= 2, "the host's pings to both members are answered (%d)" % h.count(r"pings-done"))
check(h.count(r"send-refused") == 0, "the host never sends on a connection of an earlier incarnation (%d)" % h.count(r"send-refused"))
m1.term()
m2.term()
h.term()
print("RESULT %s failures=%d" % ("PASS" if not fails else "FAIL", len(fails)))
sys.exit(1 if fails else 0)
