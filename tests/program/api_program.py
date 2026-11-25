#!/usr/bin/env python3
"""The local API server inside the program (P5): program_api.

    python3 -I tests/program/api_program.py BUILD_DIR

Runs gazpacho-test and the release gazpacho, each in a fresh data folder,
their passphrase layer the wallet's encrypted storage (B3), and talks to the API over loopback as
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
  7. the release program serves the API too, and its first run works on the
     encrypted storage (create gives 24 words, the node then starts), and its
     output has no NOTIFY lines;
  8. no passphrase and no word of the phrase in any output line; a stop is clean.

The wallet phrase is fixed (review of P5): gazpacho-test is given the new
wallet's entropy (--test-entropy-hex), so the 24 words are known. A BIP-39 word that is
also an ordinary word the program prints or the API answers ("open", "start")
would make a single-word check fail by chance, so the seed was chosen to give
24 words outside that vocabulary:

  1. python3 -I tests/program/api_program.py BUILD --dump-vocab FILE
     runs every step below with a random phrase and writes every lower-case
     word found in the output of both programs and in every API answer
     (tests/program/api_program_vocab.txt is that file);
  2. python3 -I tests/program/api_program.py --choose-seed FILE
     tries SHA-256("gazpacho program_api test seed " + n) for n = 0, 1, ...
     and prints the first n whose 24 words are all outside FILE.

SEED_N below is that n. Every word of the phrase is then checked as a whole
word in all output, and so is every pair of neighbouring words.
Standard library only."""
import base64
import hashlib
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
SEED_TAG = "gazpacho program_api test seed "
SEED_N = 1   # chosen by --choose-seed (docstring)
fails = []
DUMP = []       # --dump-vocab: every output line and API answer
HERE = os.path.dirname(os.path.abspath(__file__))


def can_connect(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        return True
    except OSError:
        return False


def wordlist():
    """The BIP-39 English list, read from the interface's copy (web/js/bip39.js)."""
    text = open(os.path.join(HERE, "..", "..", "web", "js", "bip39.js"), encoding="utf-8").read()
    words = " ".join(re.findall(r'"([a-z ]+)"', text)).split()
    words = words[words.index("abandon"):][:2048]
    assert len(words) == 2048 and words[-1] == "zoo" and len(set(words)) == 2048, len(words)
    return words


def phrase_of(entropy):
    """BIP-39: 256 bits of entropy and 8 bits of SHA-256 checksum, 24 words of 11 bits."""
    wl = wordlist()
    bits = int.from_bytes(entropy, "big") << 8 | hashlib.sha256(entropy).digest()[0]
    return [wl[(bits >> (11 * (23 - i))) & 2047] for i in range(24)]


def seed_of(n):
    return hashlib.sha256((SEED_TAG + str(n)).encode()).digest()


def choose_seed(vocab_file):
    vocab = set(open(vocab_file, encoding="utf-8").read().split())
    for n in range(1000000):
        w = phrase_of(seed_of(n))
        if not vocab.intersection(w):
            print("SEED_N = %d" % n)
            print(" ".join(w))
            return 0
    return 1


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
    def __init__(self, exe, extra=(), seed=None):
        self.dir = tempfile.mkdtemp(prefix="gzapi-")
        self.data = os.path.join(self.dir, "d")
        self.port = free_port()
        self.listen = free_port()
        args = [exe, "--data-dir", self.data, "--role", "host", "--listen", "127.0.0.1:%d" % self.listen, "--no-chain",
                "--interface-port", str(self.port), "--name", "h1"] + list(extra)
        if seed is not None:              # the new wallet's entropy (gazpacho-test)
            args += ["--test-entropy-hex", seed.hex()]
        env = dict(os.environ, XDG_RUNTIME_DIR=self.dir)
        # The API's sign-in and set-up, not the tests' passphrase file.
        env.pop("GZP_TEST_PASSPHRASE_FILE", None)
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
        DUMP.append(raw.decode("utf-8", "replace"))
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

    fixed = None if DUMP_FILE or SEED_N is None else phrase_of(seed_of(SEED_N))
    p = Prog(exe_t, ("--test-kdf-floor",), seed=None if fixed is None else seed_of(SEED_N))
    try:
        m = p.wait_line(r"interface listening http://127\.0\.0\.1:(\d+)/")
        check(m is not None and int(m.group(1)) == p.port, "the program's API server listens", p.lines[-5:])
        check(p.wait_line(r"unlock encrypted-storage") is not None and p.wait_line(r"locked: waiting for the local interface"),
              "the passphrase layer is the encrypted storage, and the program waits locked for the interface")
        check(p.wait_line(r"ready incarnation=", timeout=1) is None and not can_connect(p.listen),
              "locked: no node and no listener before the set-up")
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
        create_answer = len(DUMP) - 1
        if fixed is not None:
            check(words == fixed, "the words are the fixed test phrase's")
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
        stream_bytes = buf
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
        # One owner of attempts.gza (storage 12.3): the wallet. The API server
        # keeps no count of its own in it (two writers left a block the
        # wallet read as running at the next try: review A's re-confirmation
        # follow-up, run 32).
        check(not any("wrong passphrase (" in l for l in p.lines),
              "the API server keeps no attempts count of its own: the wallet's is the one", [l for l in p.lines if "wrong passphrase (" in l][:2])
        # Obeying retry_after_s exactly, the next try is checked: here, the right
        # password signs in (the server's view of the delay and the wallet's are one).
        time.sleep(par.get("retry_after_s", 1) + 0.05)
        st, s2 = p.call("POST", "/session", {"passphrase": PASS})
        check(st == 200 and s2 and s2.get("session"), "after retry_after_s the right password is checked and signs in", (st, s2))
        p.session = keep

        # 6. lock
        st, k = p.call("POST", "/wallet/lock", {"confirm": "lock_wallet"})
        check(st == 202 and k and k.get("wallet") == "locked", "lock", k)
        p.session = None
        st, s = p.call("GET", "/status")
        check(st == 200 and s and s.get("wallet") == "locked", "the locked status without a session", s)

        # 6b. lock stops the node (unlock.h; local-api.md 4.7): a locked program
        # answers no host, and an unlock starts the node again (review M5)
        check(p.wait_line(r"node-stopped-locked") is not None, "lock stops the node", p.lines[-6:])
        # The transport's static key (from the seed; the host's long-term key)
        # goes with the lock and comes back the same at the unlock (review A's
        # confirmation of PR 54, M-1).
        hk = p.wait_line(r"host key=([0-9a-f]{66})", timeout=1)
        check(p.wait_line(r"transport-key wiped zero=1 peers=0", timeout=5) is not None,
              "lock wipes the transport's static key; no transport holds it")
        check(p.wait_line(r"ready incarnation=1 ") is not None and not can_connect(p.listen),
              "a locked program answers no host: its listener is closed")
        time.sleep(1.2)
        st, s = p.call("POST", "/session", {"passphrase": PASS})
        check(st == 200 and s and s.get("session"), "unlock", (st, s))
        p.session = s.get("session") if s else None
        check(p.wait_line(r"node-starting-unlocked") is not None, "an unlock starts the node again")
        end = time.time() + 15
        while time.time() < end and not can_connect(p.listen):
            time.sleep(0.2)
        check(can_connect(p.listen), "the listener is open again after the unlock")
        check(p.wait_line(r"ready incarnation=2 ") is not None, "the node started as a new incarnation")
        rk = p.wait_line(r"transport-key restored key=([0-9a-f]{66})", timeout=1)
        check(hk is not None and rk is not None and rk.group(1) == hk.group(1),
              "the unlock derives the same transport key again from the seed", (hk and hk.group(1), rk and rk.group(1)))
        st, s = p.call("GET", "/status")
        check(st == 200 and s and s.get("wallet") == "ready", "status after the unlock: ready", s and s.get("wallet"))
    finally:
        rc = p.stop()
    check(rc == 0, "a clean stop", rc)
    out = "\n".join(p.lines)
    check(PASS not in out, "the passphrase is in no output line")
    # Every word of the phrase as a whole word, and every pair of neighbours.
    # The phrase is fixed and outside the program's vocabulary (docstring), so
    # a single word found here is a leak, not chance.
    flat = " " + re.sub(r"[^a-z]+", " ", out.lower()) + " "
    if fixed is not None:
        single = sorted(w for w in set(words) if " %s " % w in flat)
        check(len(words) == 24 and not single, "no word of the 24 is in the output", single)
    pairs = [" %s %s " % (words[i], words[i + 1]) for i in range(len(words) - 1)]
    leaked = [x.strip() for x in pairs if x in flat]
    check(len(words) == 24 and not leaked, "no two neighbouring words of the 24 are in the output", leaked)
    DUMP.extend(p.lines)
    check(re.search(r"shutdown node-stopped .*\n(.*\n)*.*shutdown lock-released", out) is not None, "the shutdown order holds")
    # the API server closes before the chain worker is joined, and both before
    # the connections (contract-v2.md 4); each line reads the others' state (review L2)
    order = [m.group(1) for m in (re.search(r"\bshutdown (\S+)", l) for l in p.lines) if m]
    check(order[:6] == ["node-stopped", "api-closed", "chain-closed", "connections-closed", "storage-closed", "lock-released"],
          "the shutdown order includes the API server and the chain worker", order)
    check(any(re.search(r"shutdown api-closed api=0 chain=1\b", l) for l in p.lines), "the API closes while the chain worker still runs")
    check(any(re.search(r"shutdown chain-closed api=0 chain=0\b", l) for l in p.lines), "the chain worker is joined after the API")

    # the entropy and the seed in hex (either case) or base64, and the words, in
    # the output, the event stream and every API answer but create's (review L3)
    if fixed is not None:
        ent = seed_of(SEED_N)
        seed = hashlib.pbkdf2_hmac("sha512", " ".join(fixed).encode(), b"mnemonic", 2048)
        forms = []
        for b in (ent, seed):
            forms += [b.hex(), b.hex().upper(), base64.b64encode(b).decode(), base64.urlsafe_b64encode(b).decode().rstrip("=")]
        texts = {"output": out, "event stream": stream_bytes.decode("utf-8", "replace")}
        for i, a in enumerate(DUMP):
            if i != create_answer:
                texts["answer %d" % i] = a
        found = [(k, f[:12]) for k, t in texts.items() for f in forms if f in t]
        check(not found, "neither the entropy nor the seed, in hex or base64, anywhere", found)
        wflat = {k: " " + re.sub(r"[^a-z]+", " ", t.lower()) + " " for k, t in texts.items() if k != "output"}
        found = sorted({(k, w) for k, t in wflat.items() for w in set(fixed) if " %s " % w in t})
        check(not found, "no word of the 24 in the event stream or in any answer but create's", found)
    shutil.rmtree(p.dir, ignore_errors=True)

    # 7. the release program: its first run on the encrypted storage
    q = Prog(exe_r)
    try:
        check(q.wait_line(r"interface listening") is not None, "the release program serves the API", q.lines[-5:])
        check(q.wait_line(r"unlock encrypted-storage") is not None, "release: the passphrase layer is the encrypted storage")
        st, s = q.call("GET", "/session")
        check(st == 200 and s and s.get("wallet") == "none", "release: no wallet at first", s)
        check(q.wait_line(r"ready incarnation=", timeout=1) is None, "release: no node before the set-up")
        page = open(os.path.join(q.data, "first-run.html")).read()
        tok = re.search(r"#start=([A-Za-z0-9_-]{43})", page).group(1)
        st, s = q.call("POST", "/session/start", {"start_token": tok})
        q.session = s["session"] if s else None
        st, c = q.call("POST", "/wallet/create", {"confirm": "create_wallet", "passphrase": PASS, "confirm_passphrase": PASS})
        check(st == 200 and c and len(c.get("words", [])) == 24, "release: create gives the 24 words", st)
        check(q.wait_line(r"ready incarnation=1 ", timeout=60) is not None, "release: the node starts after the set-up", q.lines[-5:])
        files = os.listdir(q.data)
        check(all(f in files for f in ("keys.gzk", "journal.gzj", "starts.gzs", "attempts.gza")) and
              not any(f.endswith(".standin") for f in files), "release: the encrypted storage's files, no stand-in", files)
    finally:
        q.stop()
    check(not any(l.find("notify code=") >= 0 for l in q.lines), "release: no NOTIFY output lines (N1)")
    check(not any("TEST ONLY" in l for l in q.lines) and not any("TEST ONLY" in l for l in p.lines), "no stand-in in either build")
    check(PASS not in "\n".join(q.lines), "release: the passphrase is in no output line")
    shutil.rmtree(q.dir, ignore_errors=True)
    DUMP.extend(q.lines)

    if DUMP_FILE:
        vocab = set(re.findall(r"[a-z]+", "\n".join(DUMP).lower())) - set(words)
        with open(DUMP_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(vocab)) + "\n")
        print("wrote %d words to %s" % (len(vocab), DUMP_FILE))

    if fails:
        print("FAIL: %d of the checks" % len(fails))
        return 1
    print("PASS: the program's API server")
    return 0


DUMP_FILE = None
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--choose-seed":
        sys.exit(choose_seed(sys.argv[2]))
    if len(sys.argv) == 4 and sys.argv[2] == "--dump-vocab":
        DUMP_FILE = sys.argv[3]
    sys.exit(main())
