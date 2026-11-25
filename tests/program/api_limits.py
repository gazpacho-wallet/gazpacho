#!/usr/bin/env python3
"""The local API server under load, inside the program: program_api_limits.

    python3 -I tests/program/api_limits.py BUILD_DIR

1. The poll set holds the network's and the API server's descriptors at once
   (review of PR 51, L2/P08): the network is filled to its maximum with idle
   peers, then a fresh API request must still be answered.
2. Browser clients that do not read, or that send a request one byte at a
   time, never stall the program's loop (review of PR 51, the slow-client
   probe): its test timer keeps firing on time, and a fresh request is
   answered at once. The chain worker is a thread of its own; it gives the loop
   events through the same poll, so a loop that keeps its timers keeps them.
Standard library only."""
import http.client
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

BUILD = sys.argv[1] if len(sys.argv) > 1 else "build"
EXE = os.path.join(BUILD, "program", "gazpacho-test")
fails = []


def check(cond, what, extra=""):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails.append(what)
        if extra:
            print("     " + str(extra)[:600])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Prog:
    def __init__(self, extra):
        self.dir = tempfile.mkdtemp(prefix="gzlim-")
        self.port, self.listen = free_port(), free_port()
        args = [EXE, "--data-dir", os.path.join(self.dir, "d"), "--role", "host", "--listen", "127.0.0.1:%d" % self.listen,
                "--no-chain", "--interface-port", str(self.port), "--name", "h1", "--max-per-address", "0"] + extra
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, XDG_RUNTIME_DIR=self.dir), text=True)
        self.lines = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            self.lines.append((time.monotonic(), line.rstrip("\n")))

    def wait_line(self, pattern, timeout=15):
        end, rx = time.time() + timeout, re.compile(pattern)
        while time.time() < end:
            for _, l in list(self.lines):
                m = rx.search(l)
                if m:
                    return m
            time.sleep(0.05)
        return None

    def version(self, timeout):
        """GET /version on a fresh connection; the seconds it took, or None."""
        t0 = time.monotonic()
        try:
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
            c.request("GET", "/api/v1/version", None, {"Host": "127.0.0.1:%d" % self.port, "Sec-Fetch-Site": "same-origin",
                                                     "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"})
            r = c.getresponse()
            r.read()
            c.close()
            return time.monotonic() - t0 if r.status == 200 else None
        except OSError:
            return None

    def stop(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(15)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        shutil.rmtree(self.dir, ignore_errors=True)
        return self.p.returncode


def fd_cap():
    p = Prog([])
    held = []
    try:
        m = p.wait_line(r"poll-set cap=(\d+) net=(\d+) api=(\d+)")
        check(m is not None, "the program says its poll set", [l for _, l in p.lines[-5:]])
        check(p.wait_line(r"ready incarnation=1 ") is not None and p.wait_line(r"interface listening") is not None,
              "the program is ready")
        cap, net, api = (int(x) for x in m.groups()) if m else (0, 0, 0)
        check(cap >= 3 + net + api, "the cap counts the stop pipe, standard input, the chain fd, the network and the API",
              (cap, net, api))
        # the network full: as many idle peers as it holds, and a few it refuses
        for _ in range(net + 4):
            try:
                held.append(socket.create_connection(("127.0.0.1", p.listen), timeout=2))
            except OSError:
                break
        time.sleep(0.5)
        # some API connections open too
        for _ in range(4):
            try:
                held.append(socket.create_connection(("127.0.0.1", p.port), timeout=2))
            except OSError:
                break
        took = p.version(5)
        check(took is not None and took < 2, "with the network full, a fresh API request is answered", took)
        check(p.p.poll() is None, "the program still runs")
    finally:
        for s in held:
            s.close()
        rc = p.stop()
    check(rc == 0, "a clean stop", rc)


def slow_clients():
    p = Prog(["--test-timer-ms", "200"])
    socks = []
    stop = threading.Event()
    try:
        check(p.wait_line(r"interface listening") is not None and p.wait_line(r"ready incarnation=1 ") is not None,
              "the program is ready")
        host = "Host: 127.0.0.1:%d\r\n" % p.port
        # 30 clients that send a request one byte every half second
        for _ in range(30):
            try:
                s = socket.create_connection(("127.0.0.1", p.port), timeout=2)
                socks.append((s, ("GET /api/v1/status HTTP/1.1\r\n" + host).encode()))
            except OSError:
                break
        # 10 clients that ask for the page and its scripts and never read
        for _ in range(10):
            try:
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                s.settimeout(2)
                s.connect(("127.0.0.1", p.port))
                s.sendall(("GET / HTTP/1.1\r\n" + host + "Sec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\n"
                           "Sec-Fetch-Dest: document\r\n\r\n").encode() * 8)
                socks.append((s, None))
            except OSError:
                break

        def drip():
            i = 0
            while not stop.is_set():
                for s, msg in socks:
                    if msg and i < len(msg):
                        try:
                            s.send(msg[i:i + 1])
                        except OSError:
                            pass
                i += 1
                stop.wait(0.5)

        connected = time.monotonic()
        threading.Thread(target=drip, daemon=True).start()
        time.sleep(1.0)
        t0 = time.monotonic()
        time.sleep(4.0)
        t1 = time.monotonic()
        fired = [t for t, l in list(p.lines) if "test-timer fired" in l and t0 <= t <= t1]
        gaps = [b - a for a, b in zip(fired, fired[1:])]
        check(len(fired) >= 14, "the loop's 200 ms timer keeps firing under 40 slow clients", len(fired))
        check(not gaps or max(gaps) < 0.6, "no gap between timer firings above 0.6 s", max(gaps) if gaps else None)
        # 32 open connections is the server's cap; a local process may hold
        # them (3.3, accepted in 5.7). Headers are due within 10 s: then the
        # drippers are closed, and a fresh request is answered.
        took = None
        while took is None and time.monotonic() < connected + 15:
            took = p.version(1)
            if took is None:
                time.sleep(0.25)
        check(took is not None and time.monotonic() < connected + 13,
              "once headers 10 s late are closed, a fresh request is answered", (took, time.monotonic() - connected))
        check(p.p.poll() is None, "the program still runs")
    finally:
        stop.set()
        for s, _ in socks:
            s.close()
        rc = p.stop()
    check(rc == 0, "a clean stop", rc)


def main():
    fd_cap()
    slow_clients()
    if fails:
        print("FAIL: %d of the checks" % len(fails))
        return 1
    print("PASS: the API server under load in the program")
    return 0


if __name__ == "__main__":
    sys.exit(main())
