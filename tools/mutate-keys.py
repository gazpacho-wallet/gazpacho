#!/usr/bin/env python3
"""Mutation run for the key port (P8; docs/notes/keys.md 10).

Each line of tests/program/keys_mutants.txt is a deliberate small fault:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
OLD must occur exactly once in FILE, or N says which occurrence (1-based);
\\n in OLD or NEW is a newline. Each mutant is applied in a scratch copy of
the source tree (never the source tree itself), the affected targets are
rebuilt there incrementally, and the key port's tests run; a mutant no test
notices is a survivor.

usage: tools/mutate-keys.py SOURCE-DIR SCRATCH-DIR [NAME...]
"""
import os
import shutil
import subprocess
import sys

TARGETS = ["test_program_keys", "test_program_keys_rare", "fuzz_keys", "test_program_net", "gazpacho-test"]
TESTS = [  # name, argv (relative to the build), fast ones first
    ("keys", ["program/test_program_keys"]),
    ("keys_rare", ["program/test_program_keys_rare"]),
    ("net", ["program/test_program_net"]),
    ("fuzz", ["program/fuzz_keys", "4000"]),
    ("vectors", [sys.executable, "-I", "{src}/tools/keys-vectors.py", "--check", "{src}/tests/program/keys_vectors.h"]),
    ("derived_keys", [sys.executable, "-I", "{src}/tests/program/derived_keys.py", "program/gazpacho-test", "{work}/dk"]),
]


def unescape(t):
    out, i = [], 0
    while i < len(t):
        if t[i] == "\\" and i + 1 < len(t):
            out.append("\n" if t[i + 1] == "n" else t[i + 1])
            i += 2
        else:
            out.append(t[i])
            i += 1
    return "".join(out)


def load(path):
    ms = []
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            p = line.split("\t")
            ms.append((p[0], p[1], unescape(p[2]), unescape(p[3]), int(p[4]) if len(p) > 4 else None))
    return ms


def apply(text, old, new, nth):
    c = text.count(old)
    if nth is None:
        return text.replace(old, new) if c == 1 else None
    if c < nth:
        return None
    at = -1
    for _ in range(nth):
        at = text.index(old, at + 1)
    return text[:at] + new + text[at + len(old):]


def run(argv, cwd, timeout):
    try:
        return subprocess.run(argv, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return -1


def main():
    src, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    only = set(sys.argv[3:])
    tree, build = os.path.join(work, "tree"), os.path.join(work, "build")
    if not os.path.isdir(tree):
        shutil.copytree(src, tree, ignore=shutil.ignore_patterns(".git", "build*"))
    if not os.path.isdir(build):
        subprocess.check_call(["cmake", "-S", tree, "-B", build, "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DGZ_MUTATION_BUILD=ON", "-DGZ_VALGRIND_TESTS=OFF"],
                              stdout=subprocess.DEVNULL)
    subprocess.check_call(["cmake", "--build", build, "-j3", "--target"] + TARGETS, stdout=subprocess.DEVNULL)
    survivors, killed, broken = [], 0, []
    for name, rel, old, new, nth in load(os.path.join(src, "tests/program/keys_mutants.txt")):
        if only and name not in only:
            continue
        path = os.path.join(tree, rel)
        with open(path) as f:
            orig = f.read()
        text = apply(orig, old, new, nth)
        if text is None:
            broken.append((name, "old text not found once"))
            continue
        with open(path, "w") as f:
            f.write(text)
        try:
            if run(["cmake", "--build", build, "-j3", "--target"] + TARGETS, build, 900) != 0:
                print("%-40s killed by the compiler" % name)
                killed += 1
                continue
            by = None
            for tname, argv in TESTS:
                argv = [a.format(src=tree, work=work) for a in argv]
                if run(argv, build, 600) != 0:
                    by = tname
                    break
            if by:
                killed += 1
                print("%-40s killed by %s" % (name, by))
            else:
                survivors.append(name)
                print("%-40s SURVIVED" % name)
        finally:
            with open(path, "w") as f:
                f.write(orig)
            sys.stdout.flush()
    subprocess.call(["cmake", "--build", build, "-j3", "--target"] + TARGETS, stdout=subprocess.DEVNULL)
    print("mutants: %d killed, %d survived %r, %d not applied %r" % (killed, len(survivors), survivors, len(broken),
                                                                     broken))
    return 1 if survivors or broken else 0


if __name__ == "__main__":
    sys.exit(main())
