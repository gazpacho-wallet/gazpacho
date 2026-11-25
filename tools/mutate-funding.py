#!/usr/bin/env python3
"""Mutation run for the funding engine (core/funding).

Each line of tests/funding/funding_mutants.txt is a deliberate small fault:

    NAME ## FILE ## OLD ## NEW [## N]

OLD must occur exactly once in FILE (a path under core/funding), or N says
which occurrence (1-based). Each mutant is applied to a scratch copy (never
to the source tree), compiled with the C compiler alone together with the
contract and the tree library, and test_funding and test_funding_model are
run. A mutant neither notices is a survivor; one that does not compile tests
nothing and is reported apart. Every survivor must be triaged in
tests/funding/funding_mutants.txt (a "# survivor:" note) or killed by a test.

usage: tools/mutate-funding.py [-j N] [NAME...]
Exits 1 if any mutant survived without a triage note, or did not compile.
"""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUND = os.path.join(ROOT, "core", "funding")
LIST = os.path.join(ROOT, "tests", "funding", "funding_mutants.txt")
CC = os.environ.get("CC", "cc")
OTHER = [os.path.join(ROOT, "core", "gazpacho", f) for f in ("action.c", "envelope.c")] + \
        [os.path.join(ROOT, "core", "tree", f) for f in ("sha256.c", "terms.c", "shape.c", "model.c", "checks.c", "exit.c")]
INC = ["-I" + os.path.join(ROOT, p) for p in ("core/gazpacho/include", "core/tree/include", "tests/funding")]
NL = chr(92) + "n"


def load():
    out, triaged = [], set()
    with open(LIST) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if line.startswith("# survivor:"):
                triaged.add(line.split()[2])
                continue
            if not line or line.startswith("#"):
                continue
            part = line.split(" ## ")
            if len(part) not in (4, 5):
                sys.exit("funding_mutants.txt:%d: expected NAME ## FILE ## OLD ## NEW [## N]" % n)
            name, path, old, new = part[:4]
            out.append((name, path, old.replace(NL, "\n"), new.replace(NL, "\n"), int(part[4]) if len(part) == 5 else 0))
    return out, triaged


def run_one(m):
    name, path, old, new, which = m
    work = tempfile.mkdtemp(prefix="gz-mutf-")
    try:
        src = os.path.join(work, "funding")
        shutil.copytree(FUND, src)
        target = os.path.join(src, path)
        text = open(target).read()
        count = text.count(old)
        if which == 0 and count != 1:
            return name, "bad-list (%d matches)" % count
        if which and count < which:
            return name, "bad-list (%d matches)" % count
        pos = -1
        for _ in range(which or 1):
            pos = text.index(old, pos + 1)
        open(target, "w").write(text[:pos] + new + text[pos + len(old):])
        srcs = [os.path.join(src, "funding.c"), os.path.join(src, "txsize.c")] + OTHER
        inc = ["-I" + os.path.join(src, "include")] + INC
        for t, args in (("test_funding", []), ("test_funding_model", ["60"])):
            exe = os.path.join(work, t)
            r = subprocess.run([CC, "-std=c11", "-O1", "-w", "-o", exe] + inc + srcs +
                               [os.path.join(ROOT, "tests", "funding", t + ".c")], capture_output=True)
            if r.returncode != 0:
                return name, "no-compile"
            try:
                r = subprocess.run([exe] + args, capture_output=True, timeout=300)
            except subprocess.TimeoutExpired:
                return name, "killed (timeout)"
            if r.returncode != 0:
                return name, "killed (%s)" % t
        return name, "SURVIVED"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    args = sys.argv[1:]
    jobs = 2
    if args[:1] == ["-j"]:
        jobs, args = int(args[1]), args[2:]
    mutants, triaged = load()
    if args:
        mutants = [m for m in mutants if m[0] in args]
    bad = 0
    counts = {}
    with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
        for name, res in ex.map(run_one, mutants):
            kind = res.split()[0]
            if kind == "SURVIVED" and name in triaged:
                res, kind = "survived (triaged)", "triaged"
            counts[kind] = counts.get(kind, 0) + 1
            print("%-40s %s" % (name, res), flush=True)
            if kind in ("SURVIVED", "no-compile", "bad-list"):
                bad += 1
    print("mutants: %d; %s" % (len(mutants), ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
