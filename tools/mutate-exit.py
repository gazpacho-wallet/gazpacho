#!/usr/bin/env python3
"""Mutation run for the exit engine (core/exit), as the CTest test exit_mutants.

Each line of tests/exit/exit_mutants.txt is a deliberate small fault:

    NAME ## FILE ## OLD ## NEW [## N]

OLD must occur exactly once in FILE (a path under core/exit), or N says which
occurrence (1-based). Each mutant is applied to a scratch copy (never to the
source tree), the engine alone is compiled with the C compiler, and linked
with the test's object and the libraries the build already made (named in
the configuration file CMake writes); then test_exit_engine runs. A mutant the
test does not notice is a survivor; one that does not compile tests nothing
and is reported apart. Every survivor must be triaged in
tests/exit/exit_mutants.txt (a "# survivor: NAME why" note) or killed by a test.

usage: tools/mutate-exit.py --cfg FILE [-j N] [NAME...]
Exits 1 if any mutant survived without a triage note, or did not compile.
Standard library only.
"""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXIT = os.path.join(ROOT, "core", "exit")
LIST = os.path.join(ROOT, "tests", "exit", "exit_mutants.txt")
INC = ["-I" + os.path.join(ROOT, p) for p in ("core/gazpacho/include", "core/tree/include")]
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
                sys.exit("exit_mutants.txt:%d: expected NAME ## FILE ## OLD ## NEW [## N]" % n)
            name, path, old, new = part[:4]
            out.append((name, path, old.replace(NL, "\n"), new.replace(NL, "\n"), int(part[4]) if len(part) == 5 else 0))
    return out, triaged


def config(path):
    cfg = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                cfg[k] = [x for x in v.split(";") if x]
    for k in ("cc", "obj", "lib"):
        if not cfg.get(k):
            sys.exit("%s: no %s" % (path, k))
    return cfg


def run_one(m, cfg):
    name, path, old, new, which = m
    work = tempfile.mkdtemp(prefix="gz-mute-")
    try:
        src = os.path.join(work, "exit")
        shutil.copytree(EXIT, src)
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
        obj = os.path.join(work, "exit_engine.o")
        exe = os.path.join(work, "test_exit_engine")
        cc = cfg["cc"][0]
        flags = cfg.get("flags", [])
        r = subprocess.run([cc] + flags + ["-std=c11", "-O1", "-w", "-c", "-o", obj, "-I" + os.path.join(src, "include")] + INC +
                           [os.path.join(src, "exit_engine.c")], capture_output=True)
        if r.returncode != 0:
            return name, "no-compile"
        r = subprocess.run([cc] + flags + ["-o", exe, obj] + cfg["obj"] + ["-Wl,--start-group"] + cfg["lib"] +
                           ["-Wl,--end-group", "-lpthread", "-ldl", "-lm"], capture_output=True)
        if r.returncode != 0:
            return name, "no-link: " + r.stderr.decode(errors="replace")[-300:]
        try:
            r = subprocess.run([exe], capture_output=True, timeout=300)
        except subprocess.TimeoutExpired:
            return name, "killed (timeout)"
        if r.returncode != 0:
            return name, "killed"
        return name, "SURVIVED"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    args = sys.argv[1:]
    jobs, cfg_path = 4, None
    while args[:1] in (["-j"], ["--cfg"]):
        if args[0] == "-j":
            jobs = int(args[1])
        else:
            cfg_path = args[1]
        args = args[2:]
    if not cfg_path:
        sys.exit(__doc__)
    cfg = config(cfg_path)
    mutants, triaged = load()
    if args:
        mutants = [m for m in mutants if m[0] in args]
    bad = 0
    counts = {}
    with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
        for name, res in ex.map(lambda m: run_one(m, cfg), mutants):
            kind = res.split()[0].rstrip(":")
            if kind == "SURVIVED" and name in triaged:
                res, kind = "survived (triaged)", "triaged"
            counts[kind] = counts.get(kind, 0) + 1
            print("%-40s %s" % (name, res), flush=True)
            if kind in ("SURVIVED", "no-compile", "no-link", "bad-list"):
                bad += 1
    print("mutants: %d; %s" % (len(mutants), ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
