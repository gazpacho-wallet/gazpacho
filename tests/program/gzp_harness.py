"""Shared helpers for the multi-process tests of the gazpacho program.

Standard library only. Each test script puts this folder on sys.path itself
(they run with python3 -I).
"""
import hashlib
import os
import re
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

    def __init__(self, name, args, log_dir):
        self.name = name
        self.lines = []
        self.times = []
        self.started = time.time()
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
                self.times.append(time.time())
                self.cv.notify_all()
        with self.cv:
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
                if self.p.poll() is not None:
                    self.cv.wait(0.2)
                    if i >= len(self.lines):
                        return None
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
        try:
            return self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return None

    def stop(self, timeout=10):
        if self.p.poll() is None:
            self.p.terminate()
        return self.exit_code(timeout)


def run(exe, *args, timeout=30):
    r = subprocess.run([exe] + list(args), capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def kill_all(procs):
    for p in procs:
        if p and p.p.poll() is None:
            p.p.kill()
