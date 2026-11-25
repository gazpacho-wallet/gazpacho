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
  4. the core's view and command results (W12): lobby lists empty, a lobby
     404, the core's refusal of a member's call on a host (409 not_a_member)
     as the call's error; then a member program (its own data folder, set up
     the same way): a discovery query held and answered from the command
     result, the core's 409 busy, and an unreachable host;
  5. a wrong passphrase: 401 with retry_after_s and wrong_in_row (open point 42);
  6. lock: the wallet reads locked without a session;
  7. the release program serves the API too, without the stand-in: sign-in is
     refused honestly (503, not_built), and its output has no NOTIFY lines;
  8. no passphrase and no word of the phrase in any output line; a stop is clean.

The wallet phrase is fixed (review of P5): the data folder gets the stand-in
seed file before the start, so the 24 words are known. A BIP-39 word that is
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
SEED_N = 3   # chosen by --choose-seed (docstring)
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


# the generator point: a valid key that no host here holds
NOBODY_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def set_up(prog):
    """First run for a second program: the start token, create, finish-setup."""
    if prog.wait_line(r"interface listening") is None:
        return False
    page = open(os.path.join(prog.data, "first-run.html")).read()
    tok = re.search(r"#start=([A-Za-z0-9_-]{43})", page).group(1)
    st, s = prog.call("POST", "/session/start", {"start_token": tok})
    prog.session = s["session"] if st == 200 and s else None
    st, c = prog.call("POST", "/wallet/create", {"confirm": "create_wallet", "passphrase": PASS, "confirm_passphrase": PASS})
    prog.create_answer = len(prog.answers) - 1
    prog.words = (c or {}).get("words", [])
    if st != 200:
        return False
    st, f = prog.call("POST", "/wallet/finish-setup", {"preset": "everyday", "find": "browse"})
    return st == 200 and f and f.get("state") == "ready"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Prog:
    def __init__(self, exe, extra=(), seed=None, role="host", dump=True):
        self.dir = tempfile.mkdtemp(prefix="gzapi-")
        self.data = os.path.join(self.dir, "d")
        if seed is not None:              # the stand-in seed file, as the program writes it (datadir.c)
            os.mkdir(self.data, 0o700)
            fd = os.open(os.path.join(self.data, "wallet-seed.standin"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, (seed.hex() + "\n").encode())
            os.close(fd)
        self.port = free_port()
        self.listen = free_port()
        self.dump = dump                  # its answers go into DUMP (the host's phrase checks)
        self.answers = []                 # every answer, for its own secrets scan (review of #79, L3)
        self.create_answer = None
        if role == "host":
            args = [exe, "--data-dir", self.data, "--role", "host", "--listen", "127.0.0.1:%d" % self.listen, "--no-chain",
                    "--interface-port", str(self.port), "--name", "h1"] + list(extra)
        else:                             # a member names a host to connect to: one nobody listens at
            args = [exe, "--data-dir", self.data, "--role", "member", "--connect", NOBODY_KEY + "@127.0.0.1:%d" % self.listen,
                    "--no-chain", "--interface-port", str(self.port), "--name", "m1"] + list(extra)
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
        if self.dump:
            DUMP.append(raw.decode("utf-8", "replace"))
        self.answers.append(raw.decode("utf-8", "replace"))
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


def member_queries(p, host):
    """Section 4 on a member: a query held and answered, busy, unreachable."""
    st, q = p.call("POST", "/discovery/query", {"host": host})
    check(st == 202 and q and q.get("query_id", "").startswith("q_") and q.get("state") == "asking",
          "a query: 202 from the core's command result, the query as the view holds it", (st, q))
    st, e = p.call("POST", "/discovery/query", {"host": host})
    check(st == 409 and e and e.get("code") == "busy", "a second query while one asks: the core's 409 busy", (st, e))
    qid = (q or {}).get("query_id", "q_0")
    end, g = time.time() + 20, None
    while time.time() < end:
        st, g = p.call("GET", "/discovery/queries/" + qid)
        if g and g.get("state") != "asking":
            break
        time.sleep(0.5)
    check(g and g.get("state") == "failed" and g.get("failed_because") == "unreachable" and g.get("lobbies") == [],
          "nobody at that address: the query failed, unreachable", g)


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
    p = Prog(exe_t, seed=None if fixed is None else seed_of(SEED_N))
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

        # 4. the core's view and its command results (W12): no lobby yet, a lobby
        # the view does not hold is 404; a refusal the core gives arrives as the
        # call's error (a query is a member's call: on this host, 409
        # not_a_member). On a member program: a held call answered from the
        # command result (202, the object it made, read back from the view), the
        # core's 409 busy, and a host that is not there: the query fails, unreachable
        st, l = p.call("GET", "/lobbies?show=all")
        check(st == 200 and l and l.get("items") == [], "lobbies: an empty list before any query", l)
        st, l = p.call("GET", "/lobbies/lob_nothing")
        check(st == 404, "a lobby the view does not hold: 404", l)
        st, e = p.call("POST", "/discovery/query", {"host": "not a host"})
        check(st == 400 and e and e.get("code") == "bad_host_address", "a host address that is not one: 400", e)
        # a draft the terms refuse (terms.md type 12: the minimum is 3 to target) cannot be
        # opened, and says why; the same draft with a minimum of 3 can
        st, pv = p.call("POST", "/host/preview", {"name": "x", "target": 3, "minimum": 2})
        check(st == 200 and pv and pv.get("can_open") is False and pv.get("cannot_open_because") == ["bad_terms"] and
              "as_members_see_it" in pv and pv["as_members_see_it"] is None,
              "a draft with minimum 2: can_open false, bad_terms, no terms to show", (st, pv))
        st, pv = p.call("POST", "/host/preview", {"name": "x", "target": 3, "minimum": 3})
        seen = (pv or {}).get("as_members_see_it") or {}
        check(st == 200 and pv and pv.get("can_open") is True and pv.get("draft_digest"),
              "the same draft with minimum 3: can_open", (st, pv))
        # 15.1: the preview shows the terms as members will see them, not signed yet (the
        # interface renders this object; without it the page stopped before the reasons)
        check(seen.get("outer", {}).get("minimum") == 3 and seen.get("outer", {}).get("target") == 3 and
              seen.get("signatures_checked") is False and seen.get("fingerprint") is None and
              "joining_fee_sat" in seen.get("ranges", {}),
              "the preview's as_members_see_it: the draft's terms, unsigned", seen)
        host = NOBODY_KEY + "@127.0.0.1:%d" % free_port()
        st, e = p.call("POST", "/discovery/query", {"host": host})
        check(st == 409 and e and e.get("code") == "not_a_member",
              "a query on a host: the core's refusal (409 not_a_member) as the call's error", (st, e))
        # the member has the same fixed phrase (its own data folder), so the
        # same whole-word scan holds for it: its output and every answer but
        # its create's carry no word of the 24 and never the passphrase
        m = Prog(exe_t, role="member", dump=False, seed=None if fixed is None else seed_of(SEED_N))
        try:
            check(set_up(m), "a member program, set up", m.lines[-5:])
            member_queries(m, host)
            # PUT /conditions names the version it changes (7.4; review of #79, L4)
            st, e = m.call("PUT", "/conditions", {"conditions": {"min_members": 2}})
            check(st == 400 and e and e.get("code") == "missing_field" and e.get("field") == "/based_on_version",
                  "conditions without based_on_version: 400, never the current version", (st, e))
        finally:
            m.stop()
        mtexts = ["\n".join(m.lines)] + [a for i, a in enumerate(m.answers) if i != m.create_answer]
        if DUMP_FILE:                         # the member's words count in the vocabulary too
            DUMP.extend(mtexts)
        check(not any(PASS in t for t in mtexts), "the member: the passphrase is in no output line and no answer")
        if fixed is not None:
            check(getattr(m, "words", None) == fixed, "the member's words are the fixed phrase's")
            mflat = [" " + re.sub(r"[^a-z]+", " ", t.lower()) + " " for t in mtexts]
            found = sorted({w for t in mflat for w in set(fixed) if " %s " % w in t})
            check(not found, "the member: no word of the 24 in its output or any answer but create's", found)
        shutil.rmtree(m.dir, ignore_errors=True)

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

        # 6b. lock stops the node (unlock.h; local-api.md 4.7): a locked program
        # answers no host, and an unlock starts the node again (review M5)
        check(p.wait_line(r"node-stopped-locked") is not None, "lock stops the node", p.lines[-6:])
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
    DUMP.extend(q.lines)

    if DUMP_FILE:
        # Every word of every answer and line but the create answer's: the run's own
        # random phrase is not taken away, so a fixed word of the program (a key such
        # as switches.chat) counts even when the run's phrase happens to hold it.
        vocab = set(re.findall(r"[a-z]+", "\n".join(t for i, t in enumerate(DUMP) if i != create_answer).lower()))
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
