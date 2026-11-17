#!/usr/bin/env python3
"""Fail if a tracked file, a link target or a commit names a real machine or a local folder.

Looks in every file `git ls-files` lists, except core/superscalar/ (imported
byte for byte, never edited) and binary files, for:

  - an IPv4 address other than 127.0.0.1, 0.0.0.0 and the three
    documentation ranges of RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24);
  - a Windows user path: a drive letter followed by the Users folder, or the
    per-user application data folder;
  - a Unix server path: an absolute path into the root user's home, a home
    folder, or the var tree (the folders of a build server), written with at
    least one name after it.

A symbolic link is checked by its target text, read from git, not by the file
it points to: a link committed by mistake names a folder of the machine it
was made on.

Four dotted numbers are not always an address. A match is skipped when it is
part of a longer dotted run (five numbers or more), sits next to letters or digits, or is
written as a version: preceded by "v", "version", "release", "since",
"OpenSSL" and the like. A line that must hold an address or a path on purpose
(a test input the code is meant to refuse, for example) carries the marker
"address-check: allow" in a comment; prefer a documentation address where one
will do. Anything else that is not an address belongs in ALLOWED below, with
the reason.

    python -I tools/check-no-addresses.py [path ...]
    python -I tools/check-no-addresses.py --rev REV [REV ...]

With no arguments it checks the tracked files; with paths, those files. With
--rev it checks, for each commit named, every file of that commit's tree
(link targets included) and the commit's message, so a branch can be checked
commit by commit before it is pushed:

    for c in $(git rev-list origin/main..HEAD); do python -I tools/check-no-addresses.py --rev $c; done

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

# Files whose server paths are kept on purpose, with the reason.
SERVER_PATH_ALLOWED = {
    # A reference fixture read by tests/test_reference_tree.c, copied as made by
    # the import run (docs/handoff/README.md); its header names the run's folder.
    "tests/reference/superscalar-tree-txids.txt",
}

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
# A Unix server path: not part of a longer path or a URL, then a name after it.
UNIX_PATH = re.compile(r"(?<![\w.~/:-])/(" + "|".join(("ro" + "ot", "ho" + "me", "v" + "ar")) +
                       r")/(?=[A-Za-z0-9._$-])")


def git(*args, data=None):
    return subprocess.run(["git", "-C", ROOT] + list(args), check=True, capture_output=True,
                          input=data).stdout


def is_allowed_v4(text):
    if text in ALLOWED_V4:
        return True
    addr = ipaddress.ip_address(text)
    return any(addr in net for net in DOC_NETS)


def check_text(name, data, link=False):
    """Findings for one file's bytes (or one link's target, or one commit message)."""
    if not link and b"\0" in data[:8192]:
        return []          # binary
    text = data.decode("utf-8", errors="replace")
    found = []
    where = name + (" (link target)" if link else "")
    for n, line in enumerate(text.splitlines(), 1):
        if MARKER in line and not link:
            continue
        for m in V4.finditer(line):
            ip = m.group(1)
            if is_allowed_v4(ip) or (name, ip) in ALLOWED:
                continue
            if VERSION_BEFORE.search(line[:m.start()]):
                continue
            found.append("%s:%d: IPv4 address %s" % (where, n, ip))
        if USERS_PATH.search(line):
            found.append("%s:%d: Windows user path" % (where, n))
        if APP_DATA_DIR.search(line):
            found.append("%s:%d: Windows application data folder" % (where, n))
        m = UNIX_PATH.search(line) if name not in SERVER_PATH_ALLOWED else None
        if m:
            found.append("%s:%d: Unix server path (/%s/...)" % (where, n, m.group(1)))
    return found


def worktree_entries(paths):
    """(path, is_link, bytes) for the tracked files, or for the paths given."""
    out = git("ls-files", "-s", "-z", *paths)
    for rec in out.decode("utf-8").split("\0"):
        if not rec:
            continue
        meta, path = rec.split("\t", 1)
        mode, sha = meta.split()[0], meta.split()[1]
        if mode == "120000":
            yield path, True, git("cat-file", "blob", sha)
            continue
        try:
            with open(os.path.join(ROOT, path), "rb") as f:
                yield path, False, f.read()
        except OSError:
            continue       # deleted in the work tree
    for path in paths:
        if not git("ls-files", "--", path).strip() and os.path.isfile(os.path.join(ROOT, path)):
            with open(os.path.join(ROOT, path), "rb") as f:     # an untracked file named on purpose
                yield path.replace("\\", "/"), os.path.islink(os.path.join(ROOT, path)), f.read()


def rev_entries(rev):
    """(path, is_link, bytes) for every blob of the commit's tree."""
    listing = []
    for rec in git("ls-tree", "-r", "-z", rev).decode("utf-8").split("\0"):
        if not rec:
            continue
        meta, path = rec.split("\t", 1)
        mode, kind, sha = meta.split()
        if kind == "blob":
            listing.append((path, mode == "120000", sha))
    if not listing:
        return
    batch = git("cat-file", "--batch", data="".join(s + "\n" for _, _, s in listing).encode())
    pos = 0
    for path, link, sha in listing:
        nl = batch.index(b"\n", pos)
        size = int(batch[pos:nl].split()[2])
        yield path, link, batch[nl + 1:nl + 1 + size]
        pos = nl + 1 + size + 1


def main(argv):
    findings = []
    checked = 0
    if argv[1:2] == ["--rev"]:
        revs = argv[2:]
        if not revs:
            print("usage: check-no-addresses.py --rev REV [REV ...]")
            return 2
        for rev in revs:
            sha = git("rev-parse", "--verify", rev + "^{commit}").decode().strip()
            findings += check_text("commit %s message" % sha[:12], git("log", "-1", "--format=%B", sha))
            for path, link, data in rev_entries(sha):
                if path.startswith(EXCLUDED_PREFIXES):
                    continue
                checked += 1
                findings += ["commit %s: %s" % (sha[:12], f) for f in check_text(path, data, link)]
    else:
        paths = [p.replace("\\", "/") for p in argv[1:]]
        for path, link, data in worktree_entries(paths):
            if path.startswith(EXCLUDED_PREFIXES):
                continue
            checked += 1
            findings += check_text(path, data, link)
    for f in findings:
        print("FOUND " + f)
    if findings:
        print("FAIL: %d finding(s) in %d files. Use 127.0.0.1 or a documentation "
              "address (192.0.2.x, 198.51.100.x, 203.0.113.x), and a path relative "
              "to the repository." % (len(findings), checked))
        return 1
    print("PASS: %d files name no real address, no local user path and no server path" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
