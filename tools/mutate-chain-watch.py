#!/usr/bin/env python3
"""Mutation run for the chain worker and the watch engine (ports/chain).

Each line of ports/chain/tests/watch_mutants.txt is a deliberate small fault:

    NAME ## FILE ## OLD ## NEW [## N]

OLD must occur exactly once in FILE (a path under ports/chain), or N says
which occurrence (1-based). "\n" in OLD or NEW is a newline. Each mutant is
applied to a scratch copy of ports/chain (never to the source tree), the
library and two test programs are compiled there with the C compiler alone,
and the tests are run: chain_test_watch (the engine, exact event sequences)
and then chain_test_chainw (the worker thread). A mutant neither notices is
a survivor. A mutant that does not compile is reported apart: it tests
nothing.

usage: tools/mutate-chain-watch.py [-j N] [NAME...]
Prints one line per mutant and the counts; exits 1 if any survived or did
not compile. Standard library only.
"""
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = os.path.join(ROOT, "ports", "chain")
LIB = ["chain.c", "headers.c", "verify.c", "json.c", "esplora.c", "multi.c", "watch.c",
       "chainw.c", "tests/test_support.c", "tests/sim.c"]
TESTS = [("watch", "tests/test_watch.c", 120), ("chainw", "tests/test_chainw.c", 300)]
CC = os.environ.get("CC", "cc")
NL_MARK = chr(92) + "n"  # how a newline is written in the list


def load():
    out = []
    with open(os.path.join(PORT, "tests", "watch_mutants.txt")) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            part = line.split(" ## ")
            if len(part) not in (4, 5):
                sys.exit("watch_mutants.txt:%d: expected NAME ## FILE ## OLD ## NEW [## N]" % n)
            name, path, old, new = part[:4]
            which = int(part[4]) if len(part) == 5 else 0
            out.append((name, path, old.replace(NL_MARK, chr(10)), new.replace(NL_MARK, chr(10)), which))
    return out


def run_one(mutant):
    name, path, old, new, which = mutant
    work = tempfile.mkdtemp(prefix="gz-mut-")
    try:
        src = os.path.join(work, "chain")
        shutil.copytree(PORT, src)
        target = os.path.join(src, path)
        with open(target) as f:
            text = f.read()
        count = text.count(old)
        if count == 0 or (which == 0 and count != 1) or which > count:
            return name, "BAD-LIST", "OLD occurs %d times in %s" % (count, path)
        at = -1
        for _ in range(which or 1):
            at = text.index(old, at + 1)
        with open(target, "w") as f:
            f.write(text[:at] + new + text[at + len(old):])
        for test, source, limit in TESTS:
            exe = os.path.join(work, test)
            cmd = [CC, "-std=c11", "-O1", "-Wall", "-Wextra", "-I" + os.path.join(src, "include"),
                   '-DGZ_TEST_DATA_DIR="%s"' % os.path.join(src, "tests", "data")]
            cmd += [os.path.join(src, s) for s in LIB] + [os.path.join(src, source)]
            cmd += ["-o", exe, "-lcrypto", "-lpthread"]
            built = subprocess.run(cmd, capture_output=True, text=True)
            if built.returncode != 0:
                return name, "NO-COMPILE", built.stderr.strip().splitlines()[0][:160]
            try:
                env = dict(os.environ, GZ_CHAINW_ROUNDS="12")
                ran = subprocess.run([exe], capture_output=True, timeout=limit, env=env)
                if ran.returncode != 0:
                    return name, "caught", test
            except subprocess.TimeoutExpired:
                return name, "caught", test + " (hung)"
        return name, "SURVIVED", ""
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    args = sys.argv[1:]
    jobs = 2
    if args[:1] == ["-j"]:
        jobs = int(args[1])
        args = args[2:]
    mutants = [m for m in load() if not args or m[0] in args]
    names = [m[0] for m in mutants]
    if len(set(names)) != len(names):
        sys.exit("watch_mutants.txt: a name is used twice")
    counts = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for name, verdict, detail in pool.map(run_one, mutants):
            counts[verdict] = counts.get(verdict, 0) + 1
            print("%-10s %-28s %s" % (verdict, name, detail), flush=True)
    print("%d mutants: %d caught, %d survived, %d did not compile, %d bad list entries" % (
        len(mutants), counts.get("caught", 0), counts.get("SURVIVED", 0),
        counts.get("NO-COMPILE", 0), counts.get("BAD-LIST", 0)))
    return 0 if counts.get("caught", 0) == len(mutants) else 1


if __name__ == "__main__":
    sys.exit(main())
