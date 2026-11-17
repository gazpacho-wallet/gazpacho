#!/usr/bin/env python3
"""The local API server inside the program (P5): program_api.

    python3 -I tests/program/api_program.py BUILD_DIR

Runs gazpacho-test (with the TEST-ONLY passphrase stand-in) and the release
gazpacho, each in a fresh data folder, and talks to the API over loopback as
the interface does (Host, Origin, fetch metadata, the session header):

  1. version and network; mainnet refused before anything opens;
  2. first run from the redirect file the program wrote: the start token,
     create (the 24 words), status (created_not_finished, the chain view
     honestly "unreachable" with --no-chain), finish-setup, then ready;
  3. the event stream, read through the program's one poll loop, carries the
     status change that finish-setup makes;
  4. what waits for the core's view objects (P6a): lobby lists are empty, a
     lobby is 404, an acting call is 501 not_in_this_release with needs;
  5. a wrong passphrase: 401 with retry_after_s and wrong_in_row (open point 42);
  6. lock: the wallet reads locked without a session;
  7. the release program serves the API too, without the stand-in: sign-in is
     refused honestly (503, not_built), and its output has no NOTIFY lines;
  8. no passphrase and no word in any output line; a stop is clean.
Standard library only."""
import http.client
import json
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
PASS = "a long enough passphrase, test only"
fails = []


def check(cond, what, extra=""):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails.append(what)
        if extra:
            print("     " + str(extra)[:500])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Prog:
    def __init__(self, exe, extra=()):
        self.dir = tempfile.mkdtemp(prefix="gzapi-")
        self.data = os.path.join(self.dir, "d")
        self.port = free_port()
        args = [exe, "--data-dir", self.data, "--role", "host", "--listen", "127.0.0.1:%d" % free_port(), "--no-chain",
                "--interface-port", str(self.port), "--name", "h1"] + list(extra)
        env = dict(os.environ, XDG_RUNTIME_DIR=self.dir)
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True)
        self.lines = []
        self.t = threading.Thread(target=self._read, daemon=True)
        self.t.start()
        self.session = None

    def _read(self):
        for line in self.p.stdout:
            self.lines.append(line.rstrip("\n"))

    def wait_line(self, pattern, timeout=15):
        end = time.time() + timeout
        rx = re.compile(pattern)
        while time.time() < end:
            for l in list(self.lines):
                m = rx.search(l)
                if m:
                    return m
            time.sleep(0.05)
        return None

    def call(self, method, path, body=None, session=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        h = {"Host": "127.0.0.1:%d" % self.port, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
             "Sec-Fetch-Dest": "empty"}
        if method != "GET":
            h["Origin"] = "http://127.0.0.1:%d" % self.port
        if session and self.session:
            h["X-Gazpacho-Session"] = self.session
        data = None
        if body is not None:
            data = json.dumps(body)
            h["Content-Type"] = "application/json"
        c.request(method, "/api/v1" + path, data, h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            j = json.loads(raw) if raw else None
        except ValueError:
            j = None
        return r.status, j

    def stop(self):
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(15)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        self.t.join(5)
        return self.p.returncode


def events(prog, until_topic, timeout=10):
    """Read the event stream with the session header until a change of the topic."""
    s = socket.create_connection(("127.0.0.1", prog.port), timeout=timeout)
    req = ("GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: same-origin\r\n"
           "Sec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nX-Gazpacho-Session: %s\r\n\r\n") % (prog.port, prog.session)
    s.sendall(req.encode())
    got = b""
    end = time.time() + timeout
    return s, got, end


def main():
    exe_t = os.path.join(BUILD, "program", "gazpacho-test")
    exe_r = os.path.join(BUILD, "program", "gazpacho")

    # 1. mainnet refused before anything opens
    d = tempfile.mkdtemp(prefix="gzapi-main-")
    r = subprocess.run([exe_t, "--data-dir", os.path.join(d, "x"), "--role", "member", "--network", "mainnet", "--no-chain"],
                       capture_output=True, text=True, timeout=20)
    check(r.returncode != 0 and "refusing" in r.stderr and "mainnet" in r.stderr, "mainnet is refused", r.stderr)
    check(not os.path.exists(os.path.join(d, "x")), "nothing opened for mainnet")
    shutil.rmtree(d, ignore_errors=True)

    p = Prog(exe_t)
    try:
        m = p.wait_line(r"interface listening http://127\.0\.0\.1:(\d+)/")
        check(m is not None and int(m.group(1)) == p.port, "the program's API server listens", p.lines[-5:])
        check(p.wait_line(r"unlock stand-in: TEST ONLY") is not None, "the test build says its passphrase layer is a stand-in")
        st, v = p.call("GET", "/version")
        check(st == 200 and v and v.get("network") == "signet" and v.get("api", "").startswith("1."), "version: signet", v)
        st, s = p.call("GET", "/session")
        check(st == 200 and s and s.get("wallet") == "none", "no wallet at first", s)

        # 2. first run
        page = open(os.path.join(p.data, "first-run.html")).read()
        tok = re.search(r"#start=([A-Za-z0-9_-]{43})", page).group(1)
        st, s = p.call("POST", "/session/start", {"start_token": tok})
        check(st == 200 and s and s.get("kind") == "setup", "the start token gives a setup session", s)
        p.session = s["session"] if s else None
        st, c = p.call("POST", "/wallet/create", {"confirm": "create_wallet", "passphrase": PASS, "confirm_passphrase": PASS})
        words = c.get("words", []) if c else []
        check(st == 200 and len(words) == 24, "create gives the 24 words", st)
        st, s = p.call("GET", "/status")
        check(st == 200 and s and s.get("wallet") == "created_not_finished", "status: created, not finished", s and s.get("wallet"))
        check(s and s.get("connection", {}).get("chain", {}).get("state") == "unreachable",
              "the chain view is honest: unreachable with no chain", s and s.get("connection"))
        check(s and s.get("network", {}).get("id") == "signet", "status names the network")

        # 3. the event stream through the program's loop: finish-setup changes the status
        sock = socket.create_connection(("127.0.0.1", p.port), timeout=10)
        sock.sendall(("GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\n"
                      "Sec-Fetch-Dest: empty\r\nX-Gazpacho-Session: %s\r\n\r\n" % (p.port, p.session)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += sock.recv(4096)
        check(buf.startswith(b"HTTP/1.1 200"), "the event stream opens", buf[:80])
        st, f = p.call("POST", "/wallet/finish-setup", {"preset": "everyday", "find": "browse"})
        check(st == 200 and f and f.get("state") == "ready", "finish-setup", f)
        end = time.time() + 5
        while b'"topic":"status"' not in buf and time.time() < end:
            try:
                buf += sock.recv(4096)
            except socket.timeout:
                break
        check(b'"topic":"status"' in buf, "the stream carries the status change", buf[-200:])
        sock.close()
        st, s = p.call("GET", "/status")
        check(st == 200 and s.get("wallet") == "ready", "status: ready", s.get("wallet"))

        # 4. what waits for the core's view objects
        st, l = p.call("GET", "/lobbies?show=all")
        check(st == 200 and l and l.get("items") == [], "lobbies: an empty list until the core's views", l)
        st, l = p.call("GET", "/lobbies/lob_nothing")
        check(st == 404, "a lobby the view does not hold: 404", l)
        st, e = p.call("POST", "/discovery/query", {"host": "02" + "11" * 32 + "@127.0.0.1:9736"})
        check(st == 501 and e and e.get("code") == "not_in_this_release" and e.get("params", {}).get("needs"),
              "an acting call waits honestly: 501 with needs", e)

        # 5. a wrong passphrase: when to try again, and how many in a row
        time.sleep(1.2)
        keep = p.session
        p.session = None
        st, e = p.call("POST", "/session", {"passphrase": "not the passphrase at all"})
        par = (e or {}).get("params", {})
        check(st == 401 and e.get("code") == "wrong_passphrase" and par.get("wrong_in_row") == 1 and par.get("retry_after_s", 0) >= 1,
              "wrong passphrase: retry_after_s and wrong_in_row", e)
        p.session = keep

        # 6. lock
        st, k = p.call("POST", "/wallet/lock", {"confirm": "lock_wallet"})
        check(st == 202 and k and k.get("wallet") == "locked", "lock", k)
        p.session = None
        st, s = p.call("GET", "/status")
        check(st == 200 and s and s.get("wallet") == "locked", "the locked status without a session", s)
    finally:
        rc = p.stop()
    check(rc == 0, "a clean stop", rc)
    out = "\n".join(p.lines)
    check(PASS not in out, "the passphrase is in no output line")
    # A single BIP-39 word is often an ordinary English word ("open", "start")
    # that the log uses by itself, so the check is on the phrase: no two of
    # its words side by side, in order, in any output line (a leak of any
    # stretch of the phrase), and every word at least checked once.
    flat = " " + re.sub(r"[^a-z]+", " ", out.lower()) + " "
    pairs = [" %s %s " % (words[i], words[i + 1]) for i in range(len(words) - 1)]
    leaked = [x.strip() for x in pairs if x in flat]
    check(len(words) == 24 and not leaked, "no stretch of the 24 words is in the output", leaked)
    check(re.search(r"shutdown node-stopped .*\n(.*\n)*.*shutdown lock-released", out) is not None, "the shutdown order holds")
    shutil.rmtree(p.dir, ignore_errors=True)

    # 7. the release program
    q = Prog(exe_r)
    try:
        check(q.wait_line(r"interface listening") is not None, "the release program serves the API", q.lines[-5:])
        check(q.wait_line(r"unlock not-built") is not None, "the release program says sign-in is not built yet")
        st, s = q.call("GET", "/session")
        check(st == 200 and s and s.get("wallet") == "locked", "release: the wallet reads locked", s)
        st, e = q.call("POST", "/session", {"passphrase": PASS})
        check(st in (429, 503), "release: sign-in is refused honestly", (st, e))
        time.sleep(0.5)
    finally:
        q.stop()
    check(not any(l.find("notify code=") >= 0 for l in q.lines), "release: no NOTIFY output lines (N1)")
    check(not any("TEST ONLY" in l for l in q.lines), "release: no stand-in")
    shutil.rmtree(q.dir, ignore_errors=True)

    if fails:
        print("FAIL: %d of the checks" % len(fails))
        return 1
    print("PASS: the program's API server")
    return 0


if __name__ == "__main__":
    sys.exit(main())
