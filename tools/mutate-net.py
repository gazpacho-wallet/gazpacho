#!/usr/bin/env python3
"""Mutation run for ports/net (engineering checklist item 8).

Each line of tests/net/mutants.txt is a deliberate small fault:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
OLD must occur exactly once in FILE, or N says which occurrence (1-based).
Each mutant is applied to a scratch copy (never to the source tree), the
transport and its tests are built there, and every test is run. A mutant no
test notices is a survivor.

usage: tools/mutate-net.py SOURCE-DIR BUILD-DIR [NAME...]
BUILD-DIR is a configured CMake build, used only to find libsecp256k1.
"""
import os
import shutil
import subprocess
import sys
import tempfile

TESTS = [  # name, sources, arguments
    ("noise", ["tests/net/test_noise.c"], []),
    ("frame", ["tests/net/test_frame.c"], ["3000"]),
    ("conn", ["tests/net/test_conn.c"], []),
    ("fuzz_noise", ["tests/net/fuzz_noise.c", "tests/net/fuzz_main.c"], ["30000"]),
    ("fuzz_tlv", ["tests/net/fuzz_tlv.c", "tests/net/fuzz_main.c"], ["100000"]),
    ("gz_net", ["tools/gz-net/gz-net.c"], None),  # run through tests/net/test_gz_net.sh
]
LIB = ["ports/net/noise.c", "ports/net/frame.c", "ports/net/conn.c"]


def secp_paths(build):
    src = os.path.join(build, "_deps", "secp256k1-zkp-src")
    with open(os.path.join(build, "CMakeCache.txt")) as f:
        for line in f:
            if line.upper().startswith("FETCHCONTENT_SOURCE_DIR_SECP256K1-ZKP") and "=" in line:
                value = line.split("=", 1)[1].strip()
                if value:
                    src = value
    return os.path.join(src, "include"), os.path.join(build, "_deps", "secp256k1-zkp-build", "src", "libsecp256k1.a")


def apply(path, old, new, nth):
    with open(path) as f:
        text = f.read()
    count = text.count(old)
    if nth is None:
        if count != 1:
            return "occurs %d times" % count
        text = text.replace(old, new)
    else:
        if count < nth:
            return "occurs %d times, wanted occurrence %d" % (count, nth)
        at = -1
        for _ in range(nth):
            at = text.index(old, at + 1)
        text = text[:at] + new + text[at + len(old):]
    with open(path, "w") as f:
        f.write(text)
    return None


def run_all(work, inc, lib):
    cc = ["gcc", "-std=c11", "-O1", "-w", "-I", work + "/ports/net", "-I", work + "/core/gazpacho/include", "-I", inc]
    objs = []
    for src in LIB:
        obj = os.path.join(work, os.path.basename(src) + ".o")
        if subprocess.call(cc + ["-c", os.path.join(work, src), "-o", obj], stderr=subprocess.DEVNULL) != 0:
            return None
        objs.append(obj)
    caught = []
    for name, srcs, args in TESTS:
        exe = os.path.join(work, name + ".bin")
        if subprocess.call(cc + [os.path.join(work, s) for s in srcs] + objs + [lib, "-lcrypto", "-o", exe],
                           stderr=subprocess.DEVNULL) != 0:
            caught.append(name + "(build)")
            continue
        cmd = ["sh", os.path.join(work, "tests/net/test_gz_net.sh"), exe] if args is None else [exe] + args
        try:
            rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90, cwd=work)
        except subprocess.TimeoutExpired:
            rc = "timeout"
        if rc != 0:
            caught.append(name if rc != "timeout" else name + "(timeout)")
    return caught


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src, build = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    only = set(sys.argv[3:])
    inc, lib = secp_paths(build)
    mutants = []
    with open(os.path.join(src, "tests/net/mutants.txt")) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            nth = int(parts[4]) if len(parts) > 4 else None
            mutants.append((parts[0], parts[1], parts[2].replace("\\n", "\n"), parts[3].replace("\\n", "\n"), nth))
    survivors, killed, broken = [], 0, []
    for i, (name, path, old, new, nth) in enumerate([("baseline", None, None, None, None)] + mutants):
        if only and name not in only and name != "baseline":
            continue
        work = tempfile.mkdtemp(prefix="gz-mut-")
        try:
            for d in ("ports", "tests", "tools", "core/gazpacho/include"):
                shutil.copytree(os.path.join(src, d), os.path.join(work, d))
            if path:
                err = apply(os.path.join(work, path), old, new, nth)
                if err:
                    print("NOT APPLIED %-28s %s" % (name, err), flush=True)
                    broken.append(name)
                    continue
            caught = run_all(work, inc, lib)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        if name == "baseline":
            if caught:
                print("BASELINE FAILS: %s" % ", ".join(caught or ["library build"]))
                return 1
            print("baseline passes", flush=True)
            continue
        if caught is None:
            print("KILLED      %-28s by the compiler" % name, flush=True)
            killed += 1
        elif caught:
            print("KILLED      %-28s by %s" % (name, ", ".join(caught)), flush=True)
            killed += 1
        else:
            print("SURVIVED    %-28s %s: %r -> %r" % (name, path, old, new), flush=True)
            survivors.append(name)
    print("RESULT: %d mutants, %d killed, %d survived (%s), %d not applied"
          % (killed + len(survivors) + len(broken), killed, len(survivors), ", ".join(survivors) or "none", len(broken)))
    return 1 if survivors or broken else 0


if __name__ == "__main__":
    sys.exit(main())
