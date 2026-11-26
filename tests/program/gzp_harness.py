"""Shared helpers for the multi-process tests of the gazpacho program.

Standard library only. Each test script puts this folder on sys.path itself
(they run with python3 -I).
"""
import hashlib
import os
import re
import socket
import struct
import subprocess
import threading
import time

TIMEOUT = 60.0


class Checks:
    def __init__(self):
        self.failures = []

    def __call__(self, cond, what):
        print(("ok   " if cond else "FAIL ") + what, flush=True)
        if not cond:
            self.failures.append(what)
        return cond

    def result(self, name, logs):
        if self.failures:
            print("FAIL: %d check(s); logs in %s" % (len(self.failures), logs))
            return 1
        print("PASS: " + name)
        return 0


def peer_id(key_hex):
    return hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:16]


class Proc:
    """A process whose output lines are kept, with a timestamp each."""

    def __init__(self, name, args, log_dir, stdin=False):
        self.name = name
        self.lines = []
        self.times = []
        self.started = time.time()
        self.cv = threading.Condition()
        self.log = open(os.path.join(log_dir, name + ".log"), "a")
        args = unlock_args(args)
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  stdin=subprocess.PIPE if stdin else subprocess.DEVNULL, text=True, bufsize=1)
        self.eof = False
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def send(self, line):
        """A line on standard input (--test-commands)."""
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def _read(self):
        for line in self.p.stdout:
            line = line.rstrip("\n")
            self.log.write(line + "\n")
            self.log.flush()
            with self.cv:
                self.lines.append(line)
                self.times.append(time.time())
                self.cv.notify_all()
        with self.cv:
            self.eof = True
            self.cv.notify_all()

    def find(self, pattern, start=0):
        """(index, match) of the first match at or after `start`, or (None, None), without waiting."""
        rx = re.compile(pattern)
        with self.cv:
            for i in range(start, len(self.lines)):
                m = rx.search(self.lines[i])
                if m:
                    return i, m
        return None, None

    def wait_for(self, pattern, timeout=TIMEOUT, start=0):
        """The first match of `pattern` at or after line `start`, or None."""
        rx = re.compile(pattern)
        end = time.time() + timeout
        i = start
        with self.cv:
            while True:
                while i < len(self.lines):
                    m = rx.search(self.lines[i])
                    if m:
                        return m
                    i += 1
                if time.time() >= end:
                    return None
                if self.eof:
                    # The process has ended and every line it wrote is here.
                    return None
                if self.p.poll() is not None:
                    self.cv.wait(0.2)
                    continue
                self.cv.wait(min(end - time.time(), 0.2))

    def index_of(self, pattern, timeout=TIMEOUT, start=0):
        if self.wait_for(pattern, timeout, start) is None:
            return None
        return self.find(pattern, start)[0]

    def count(self, pattern, start=0):
        rx = re.compile(pattern)
        with self.cv:
            return sum(1 for l in self.lines[start:] if rx.search(l))

    def mark(self):
        with self.cv:
            return len(self.lines)

    def exit_code(self, timeout=TIMEOUT):
        """The exit status, once the reader has every line the process wrote:
        a check made after this sees the last line (review B of PR 41, 5)."""
        try:
            code = self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            code = None
        self.reader.join(10)
        return code

    def stop(self, timeout=10):
        if self.p.poll() is None:
            self.p.terminate()
        return self.exit_code(timeout)


def run(exe, *args, timeout=30):
    r = subprocess.run(unlock_args([exe] + list(args)), capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def kill_all(procs):
    for p in procs:
        if p and p.p.poll() is None:
            p.p.kill()


RECORD_TEST_PING = (0x7e570001, 0x7e580001)  # the test engines' ping records (test_engine.h)
PING_HEADER = 82  # clock 8, link 66, serial 8


# The wallet's passphrase for the tests (storage-encryption.md 4.1's rules:
# 15 code points or more, not common, no words of the wallet).
TEST_PASSPHRASE = "gazpacho test wallet passphrase, signet only"
_PASS_FILE = None
LAST_TEST_EXE = None


def passphrase_file():
    """A file holding the tests' passphrase, made once per run, closed to others."""
    global _PASS_FILE
    if _PASS_FILE is None:
        import tempfile
        fd, path = tempfile.mkstemp(prefix="gzp-pass-")
        os.write(fd, TEST_PASSPHRASE.encode())
        os.close(fd)
        os.chmod(path, 0o600)
        _PASS_FILE = path
    return _PASS_FILE


def unlock_args(args):
    """args, with the test unlock added for a gazpacho-test that names a data
    folder and does not choose its own passphrase file."""
    global LAST_TEST_EXE
    args = list(args)
    if args and os.path.basename(args[0]) == "gazpacho-test":
        LAST_TEST_EXE = args[0]
        if "--data-dir" in args and "--test-passphrase-file" not in args:
            args += ["--test-passphrase-file", passphrase_file(), "--test-kdf-floor"]
    return args


def dump_journal(folder, exe=None):
    """The sealed journal of a stopped program's folder, read through
    gazpacho-test --test-dump-journal: ("INCN", inc) and ("BTCH", inc, seq,
    [(type, bytes), ...]) entries, as parse_journal gives for the stand-in."""
    exe = exe or LAST_TEST_EXE
    with open(os.path.join(folder, "identity")) as f:
        role, network = f.read().split()
    r = subprocess.run(unlock_args([exe, "--data-dir", folder, "--role", role, "--network", network,
                                    "--no-chain", "--test-dump-journal"]),
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError("journal dump failed (%d): %s" % (r.returncode, r.stderr.strip()))
    out = []
    for line in r.stdout.splitlines():
        kv = dict(w.split("=", 1) for w in line.split()[1:] if "=" in w)
        if line.startswith("journal-incarnation"):
            out.append(("INCN", int(kv["inc"])))
        elif line.startswith("journal-batch"):
            out.append(("BTCH", int(kv["inc"]), int(kv["seq"]), []))
        elif line.startswith("journal-record"):
            out[-1][3].append((int(kv["type"], 16), bytes.fromhex(kv.get("hex", ""))))
    return out


def parse_journal(path):
    """The journal stand-in's entries: a list of ("INCN", inc) and
    ("BTCH", inc, seq, [(type, bytes), ...]), stopping at a torn tail."""
    folder = os.path.dirname(path)
    if (os.path.basename(path) == "journal.standin" and not os.path.exists(path)
            and os.path.exists(os.path.join(folder, "journal.gzj"))):
        # The program's store is the sealed journal: read it through the program.
        return dump_journal(folder)
    out = []
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"GZJSTAND":
        return out
    off = 16
    while off + 8 <= len(data):
        tag, ln = struct.unpack(">II", data[off:off + 8])
        if off + 8 + ln + 32 > len(data):
            break
        body = data[off + 8:off + 8 + ln]
        if hashlib.sha256(data[off:off + 8 + ln]).digest() != data[off + 8 + ln:off + 8 + ln + 32]:
            break
        if tag == 0x494e434e:
            out.append(("INCN", struct.unpack(">Q", body)[0]))
        elif tag == 0x42544348:
            inc, seq, n = struct.unpack(">QQI", body[:20])
            recs, p = [], 20
            for _ in range(n):
                t, l = struct.unpack(">II", body[p:p + 8])
                recs.append((t, body[p + 8:p + 8 + l]))
                p += 8 + l
            out.append(("BTCH", inc, seq, recs))
        off += 8 + ln + 32
    return out


def ping_payloads(entries):
    """The payloads of every ping record in parsed journal entries."""
    return [r[1][PING_HEADER:] for e in entries if e[0] == "BTCH" for r in e[3] if r[0] in RECORD_TEST_PING]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def can_connect(port):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()

def bigsize(v):
    if v < 0xfd:
        return bytes([v])
    if v <= 0xffff:
        return b"\xfd" + struct.pack(">H", v)
    if v <= 0xffffffff:
        return b"\xfe" + struct.pack(">I", v)
    return b"\xff" + struct.pack(">Q", v)


def tlv(*records):
    """A TLV stream of (type, bytes) pairs, in the order given."""
    return b"".join(bigsize(t) + bigsize(len(v)) + v for t, v in records)


def cmd(code, *records):
    """A --test-commands line: a USER_COMMAND with `code` and argument records."""
    return "cmd %04x %s" % (code, tlv(*records).hex())


def area(a):
    return (10, struct.pack(">H", a))


def journal_types(path):
    """Per batch of a stand-in journal, the list of its record types."""
    return [[r[0] for r in e[3]] for e in parse_journal(path) if e[0] == "BTCH"]
