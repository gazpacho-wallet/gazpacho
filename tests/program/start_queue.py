#!/usr/bin/env python3
"""program_start_queue (written by review B of PR 27, copied as written): the start queue, sends during a start, and test timers.
usage: queue_t.py GAZPACHO_TEST WORKDIR [ignored]. Exit 1 on any failed check."""
import os
import re
import shutil
import signal
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
        self.name, self.lines, self.cv = name, [], threading.Condition()
        d = os.path.join(WORK, name)
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        self.p = subprocess.Popen([EXE, "--data-dir", d, "--name", name] + COMMON + args,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.log = open(os.path.join(WORK, name + ".log"), "a")
        threading.Thread(target=self._rd, daemon=True).start()

    def _rd(self):
        for l in self.p.stdout:
            self.log.write(l)
            self.log.flush()
            with self.cv:
                self.lines.append(l.rstrip("\n"))
                self.cv.notify_all()

    def wait(self, rx, timeout=20):
        r = re.compile(rx)
        end = time.time() + timeout
        with self.cv:
            while time.time() < end:
                for i, l in enumerate(self.lines):
                    if r.search(l):
                        return i, l
                if self.p.poll() is not None and time.time() > end - timeout + 1:
                    self.cv.wait(0.3)
                    for i, l in enumerate(self.lines):
                        if r.search(l):
                            return i, l
                    return None, None
                self.cv.wait(0.2)
        return None, None

    def snap(self):
        with self.cv:
            return list(self.lines)

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait()

    def term(self):
        if self.p.poll() is None:
            self.p.terminate()
        try:
            return self.p.wait(15)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None


port = free_port()
# Phase 0: a host whose journal holds a ping it has not answered (it stops dead
# once the ping is durable), so its next start has a reply to resend.
h0 = P("host", ["--role", "host", "--listen", "127.0.0.1:%d" % port, "--test-crash-at-ping", "2"])
_, kl = h0.wait(r"host key=([0-9a-f]{66})")
key = re.search(r"key=([0-9a-f]{66})", kl).group(1)
m_stay = P("stay", ["--role", "member", "--connect", "%s@127.0.0.1:%d" % (key, port), "--reconnect-ms", "50",
                    "--test-pings", "3", "--test-ping-ms", "20"])
check(h0.p.wait(20) == 70, "phase 0: the host stops dead at its second ping record")
m_stay.kill()

# Phase 1: a held start (8 s) with listening, a test timer, and four members.
h = P("host", ["--role", "host", "--listen", "127.0.0.1:%d" % port, "--test-start-delay-ms", "8000",
               "--test-listen-during-start", "--test-timer-ms", "40"])
h.wait(r"start-delay")
mk = lambda name, extra: P(name, ["--role", "member", "--connect", "%s@127.0.0.1:%d" % (key, port),
                                  "--reconnect-ms", "50"] + extra)
stay = mk("stay", ["--test-burst", "3x100"])
gone = mk("gone", ["--test-burst", "3x100"])
over = mk("over", ["--test-burst", "17x65000"])
many = mk("many", ["--test-burst", "4100x200"])
for m in (stay, gone, over, many):
    m.wait(r"burst-sent", 6)
time.sleep(1.0)
_, gl = gone.wait(r" connected peer=\S+ key=\S+ outbound=1 conn=(\d+)", 1)
gone.kill()
time.sleep(0.5)
i_ready, _ = h.wait(r"ready incarnation=", 20)
check(i_ready is not None, "the held start completes")
time.sleep(2.5)
L = h.snap()
i_sd = next(i for i, l in enumerate(L) if " start-delay " in l)
during = L[i_sd:i_ready]
after = L[i_ready:]
check(not any(re.search(r" (connected peer=|disconnected peer=|test-timer fired|pong peer=)", l) for l in during),
      "nothing delivered and no test timer fired during the start")
check(any(" test-timer fired " in l for l in after), "the test timer fires after the start")
res = [l for l in during if " start-resend " in l]
drops = [l for l in during if " send-dropped " in l]
check(len(res) == 0, "the start resends nothing: a reply is pulled by the peer's hello, node.h rule 6 (%d)" % len(res))
check(len(drops) >= len(res), "every resend during the start is dropped (%d resends, %d drops)" % (len(res), len(drops)))
check(any(re.search(r"start-queue dropped conn=\d+ why=closed-during-start", l) for l in L),
      "a connection that came and went during the start is dropped")
# The host's conn ids of the members, from their keys (the 'closed' line names the key).
closed_over = [l for l in L if "start-queue closed" in l]
check(len(closed_over) >= 2, "both over-limit connections closed (17x65000 and 4100x200 with the 64-byte overhead): %d" % len(closed_over))
conn_lines = [l for l in after if re.search(r" connected peer=", l)]
gone_key = None
for l in gone.snap():
    m = re.search(r"member key=([0-9a-f]{66})", l)
    if m:
        gone_key = m.group(1)
check(gone_key is not None and not any(gone_key in l for l in conn_lines),
      "the member killed during the start is never reported connected")
many_send_refused = sum(1 for l in many.snap() if "send-refused" in l)
print("note: many member send-refused lines: %d" % many_send_refused)
# Timers across a restart: every fire after incarnation 2's ready names incarnation 2.
for m in (stay, over, many):
    m.kill()
h.term()
h2 = P("host", ["--role", "host", "--listen", "127.0.0.1:%d" % port, "--test-timer-ms", "30",
                "--test-node-error-at", "2"])
pm = mk("pinger", ["--test-pings", "5", "--test-ping-ms", "20"])
i2, l2 = h2.wait(r"ready incarnation=(\d+) .*", 20)
i3, l3 = h2.wait(r"restart-from-storage", 20)
time.sleep(1.5)
L2 = h2.snap()
readies = [(i, int(re.search(r"incarnation=(\d+)", l).group(1))) for i, l in enumerate(L2) if " ready incarnation=" in l]
check(len(readies) >= 2, "a node error restarts the host in process (%d readies)" % len(readies))
if len(readies) >= 2:
    i_r2, inc2 = readies[-1]
    fires = [int(re.search(r"incarnation=(\d+)", l).group(1)) for l in L2[i_r2:] if " test-timer fired " in l]
    check(len(fires) >= 10, "the test timer keeps firing in incarnation %d (%d fires in 1.5 s)" % (inc2, len(fires)))
    check(all(f == (inc2 & 0xffff) for f in fires), "no timer of an earlier incarnation fires after the restart")
pm.kill()
check(h2.term() == 0, "the host stops cleanly")
print("RESULT %s failures=%d" % ("PASS" if not fails else "FAIL", len(fails)))
sys.exit(1 if fails else 0)
