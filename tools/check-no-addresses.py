#!/usr/bin/env python3
"""Fail if a tracked text file names a real machine or a local user folder.

Looks in every file `git ls-files` lists, except core/superscalar/ (imported
byte for byte, never edited) and binary files, for:

  - an IPv4 address other than 127.0.0.1, 0.0.0.0 and the three
    documentation ranges of RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24);
  - a Windows user path: a drive letter followed by the Users folder, or the
    per-user application data folder.

Four dotted numbers are not always an address. A match is skipped when it is
part of a longer dotted run (five numbers or more), sits next to letters or digits, or is
written as a version: preceded by "v", "version", "release", "since",
"OpenSSL" and the like. A line that must hold an address on purpose (a test
input the code is meant to refuse, for example) carries the marker
"address-check: allow" in a comment; prefer a documentation address where one
will do. Anything else that is not an address belongs in ALLOWED below, with
the reason.

    python -I tools/check-no-addresses.py [path ...]

With no arguments it checks the tracked files; with arguments, those files.
Prints one line per finding (file:line: what) and exits 1 if there is any.
Standard library only.
"""
import ipaddress
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXCLUDED_PREFIXES = ("core/superscalar/",)

ALLOWED_V4 = {"127.0.0.1", "0.0.0.0"}
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# (path, exact text) pairs that look like an address and are not one.
ALLOWED = set()

OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
V4 = re.compile(r"(?<![\w.])(" + OCTET + r"(?:\." + OCTET + r"){3})(?![\w]|\.\d)")
VERSION_BEFORE = re.compile(
    r"(?:\bv|\bversion\s*|\brelease\s*|\bopenssl\s*|\bpython\s*|\bgcc\s*|\bclang\s*|"
    r"\bcmake\s*|\bubuntu\s*|\bnode\s*|\bsince\s*|\bbefore\s*|\bafter\s*|\buntil\s*|@)$",
    re.IGNORECASE)

# A line that holds an address on purpose (a test input the code must refuse,
# say) carries this marker in a comment.
MARKER = "address-check: allow"

# Built from pieces so this file does not match itself.
USERS_PATH = re.compile(r"\b[A-Za-z]:[\\/]+" + "Us" + r"ers[\\/]", re.IGNORECASE)
APP_DATA_DIR = re.compile("App" + "Data", re.IGNORECASE)


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"],
                         check=True, capture_output=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def is_allowed_v4(text):
    if text in ALLOWED_V4:
        return True
    addr = ipaddress.ip_address(text)
    return any(addr in net for net in DOC_NETS)


def check_file(rel):
    path = os.path.join(ROOT, rel)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []          # deleted in the work tree, or a broken link
    if b"\0" in data[:8192]:
        return []          # binary
    text = data.decode("utf-8", errors="replace")
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        if MARKER in line:
            continue
        for m in V4.finditer(line):
            ip = m.group(1)
            if is_allowed_v4(ip) or (rel, ip) in ALLOWED:
                continue
            if VERSION_BEFORE.search(line[:m.start()]):
                continue
            found.append("%s:%d: IPv4 address %s" % (rel, n, ip))
        if USERS_PATH.search(line):
            found.append("%s:%d: Windows user path" % (rel, n))
        if APP_DATA_DIR.search(line):
            found.append("%s:%d: Windows application data folder" % (rel, n))
    return found


def main(argv):
    files = argv[1:] or tracked_files()
    files = [f.replace("\\", "/") for f in files]
    findings = []
    checked = 0
    for rel in files:
        if rel.startswith(EXCLUDED_PREFIXES):
            continue
        checked += 1
        findings += check_file(rel)
    for f in findings:
        print("FOUND " + f)
    if findings:
        print("FAIL: %d finding(s) in %d files. Use 127.0.0.1 or a documentation "
              "address (192.0.2.x, 198.51.100.x, 203.0.113.x), and a path relative "
              "to the repository." % (len(findings), checked))
        return 1
    print("PASS: %d tracked files name no real address and no local user path" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
