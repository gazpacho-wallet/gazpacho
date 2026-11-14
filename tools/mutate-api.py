#!/usr/bin/env python3
"""Mutation run for ports/api, the local API server (engineering checklist
item 8).

Each line of tests/api/mutants.txt is a deliberate small fault:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
OLD must occur exactly once in FILE, or N says which occurrence (1-based).
In OLD and NEW, \\n is a newline, \\t a tab and \\\\ a backslash.

The source tree is copied once to a scratch folder (never edited in place)
and configured there; each mutant is applied to the copy, the API targets
are rebuilt, and every test labelled `api` runs (unit tests, the fuzz
targets' plain drivers, the end-to-end run against gz-api-fake). A mutant
that no test notices is a survivor. A mutant that does not build counts as
"no build", not as killed.

usage: tools/mutate-api.py SOURCE-DIR [-j N] [NAME...]
Standard library only; needs cmake, a C compiler, OpenSSL and python3.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

TARGETS = ["test_api_json", "test_api_status", "test_api_server", "test_api_peer", "gz-api-fake",
           "fuzz_api_http", "fuzz_api_json"]


def unescape(text):
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            out.append({"n": "\n", "t": "\t"}.get(text[i + 1], text[i + 1]))
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def load(src):
    mutants = []
    with open(os.path.join(src, "tests", "api", "mutants.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                raise SystemExit("bad mutant line: " + line)
            nth = int(parts[4]) if len(parts) > 4 else 0
            mutants.append((parts[0], parts[1], unescape(parts[2]), unescape(parts[3]), nth))
    return mutants


def apply(path, old, new, nth):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    count = text.count(old)
    if nth == 0:
        if count != 1:
            raise ValueError("%s: OLD occurs %d times" % (path, count))
        return text, text.replace(old, new, 1)
    pos = -1
    for _ in range(nth):
        pos = text.find(old, pos + 1)
        if pos < 0:
            raise ValueError("%s: occurrence %d not found" % (path, nth))
    return text, text[:pos] + new + text[pos + len(old):]


def run(cmd, cwd, timeout):
    try:
        r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                           errors="replace", timeout=timeout)
        return r.returncode, r.stdout
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def main(argv):
    args = argv[1:]
    jobs = "4"
    if "-j" in args:
        k = args.index("-j")
        jobs = args[k + 1]
        del args[k:k + 2]
    if not args:
        print(__doc__)
        return 2
    src = os.path.abspath(args[0])
    only = set(args[1:])
    mutants = [m for m in load(src) if not only or m[0] in only]
    work = tempfile.mkdtemp(prefix="gz-mutate-api-")
    copy = os.path.join(work, "src")
    build = os.path.join(work, "build")
    shutil.copytree(src, copy, ignore=shutil.ignore_patterns(".git", "build*", "node_modules"))
    # A mutant may leave a variable or a helper unused; that is not a test
    # finding, so the scratch copy builds without -Werror.
    top = os.path.join(copy, "CMakeLists.txt")
    with open(top, encoding="utf-8") as f:
        text = f.read()
    with open(top, "w", encoding="utf-8") as f:
        f.write(text.replace("set(GZ_NEW_CODE_WARNINGS -Wall -Wextra -Werror)", "set(GZ_NEW_CODE_WARNINGS -Wall -Wextra)"))
    code, out = run(["cmake", "-S", copy, "-B", build, "-DCMAKE_BUILD_TYPE=Release",
                     "-DGZW_BREAK_CHECKS=OFF"], work, 900)
    if code:
        print(out)
        return 1
    code, out = run(["cmake", "--build", build, "-j", jobs, "--target"] + TARGETS, work, 1800)
    if code:
        print(out)
        return 1
    code, out = run(["ctest", "--test-dir", build, "-L", "api", "--timeout", "300", "-j", "2"], work, 1800)
    if code:
        print("the unmutated tests fail; fix them first:\n" + out)
        return 1
    killed, survived, nobuild = [], [], []
    for name, rel, old, new, nth in mutants:
        path = os.path.join(copy, rel)
        start = time.time()
        try:
            original, mutated = apply(path, old, new, nth)
        except ValueError as e:
            print("%-34s BAD MUTANT: %s" % (name, e))
            nobuild.append(name)
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(mutated)
        try:
            code, out = run(["cmake", "--build", build, "-j", jobs, "--target"] + TARGETS, work, 1800)
            if code:
                verdict = "no build"
                nobuild.append(name)
            else:
                code, out = run(["ctest", "--test-dir", build, "-L", "api", "--timeout", "300", "-j", "2"],
                                work, 2400)
                if code:
                    verdict = "killed"
                    killed.append(name)
                else:
                    verdict = "SURVIVED"
                    survived.append(name)
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print("%-34s %-9s %5.0fs" % (name, verdict, time.time() - start), flush=True)
    shutil.rmtree(work, ignore_errors=True)
    print("\n%d mutants: %d killed, %d survived, %d did not build" %
          (len(mutants), len(killed), len(survived), len(nobuild)))
    if survived:
        print("survivors: " + ", ".join(survived))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
