#!/usr/bin/env python3
"""Run the compiled CTest tests of a build under valgrind's memcheck.

    python -I tools/valgrind-tests.py BUILD_DIR [-j N] [--exclude REGEX] [--include REGEX]
                                      [--args "NAME=ARG ..."]

Asks CTest for the registered tests (ctest --show-only=json-v1) and runs each
one whose command is a program built in BUILD_DIR, with the same arguments and
working directory, under

    valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite
             --track-origins=yes --quiet

Tests run through sh or python (the isolation checks, the tool scripts) are
left out: valgrind would check the shell, not our code. A test fails if it
fails on its own or if valgrind reports a memory error or a definite leak.
--args replaces one test's arguments, to run a long test on a smaller case
(valgrind is twenty to fifty times slower than the program alone). Tests run
N at a time (default: the number of processors); each test's own
output is printed in one piece when it finishes. Exits 1 if any test failed.
Standard library only.
"""
import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time

VALGRIND = ["valgrind", "--error-exitcode=99", "--leak-check=full",
            "--errors-for-leak-kinds=definite", "--track-origins=yes", "--quiet"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build")
    ap.add_argument("--exclude", default=None, help="skip tests whose name matches")
    ap.add_argument("--include", default=None, help="run only tests whose name matches")
    ap.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("-v", "--verbose", action="store_true", help="print every test's output")
    ap.add_argument("--args", action="append", default=[], metavar="NAME=ARGS",
                    help="run test NAME with these arguments instead (space-separated)")
    args = ap.parse_args()
    build = os.path.abspath(args.build)
    override = {}
    for a in args.args:
        name, _, rest = a.partition("=")
        override[name] = rest.split()

    info = json.loads(subprocess.run(
        ["ctest", "--test-dir", build, "--show-only=json-v1"],
        check=True, capture_output=True, text=True).stdout)

    jobs, skipped = [], []
    for t in info.get("tests", []):
        name, cmd = t["name"], t.get("command") or []
        if args.include and not re.search(args.include, name):
            continue
        if args.exclude and re.search(args.exclude, name):
            continue
        if not cmd or not os.path.abspath(cmd[0]).startswith(build + os.sep):
            skipped.append(name)
            continue
        cwd, will_fail = build, False
        for p in t.get("properties", []):
            if p.get("name") == "WORKING_DIRECTORY":
                cwd = p["value"]
            if p.get("name") == "WILL_FAIL":
                will_fail = str(p.get("value")).upper() in ("1", "ON", "TRUE", "YES", "Y")
        if name in override:
            cmd = cmd[:1] + override.pop(name)
            print("%s: run as %s" % (name, " ".join(os.path.basename(c) if i == 0 else c
                                                     for i, c in enumerate(cmd))))
        jobs.append((name, cmd, cwd, will_fail))
    if override:
        print("FAIL: --args names no test: %s" % ", ".join(sorted(override)))
        return 1

    def run(job):
        name, cmd, cwd, will_fail = job
        start = time.time()
        r = subprocess.run(VALGRIND + cmd, cwd=cwd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, errors="replace")
        # A WILL_FAIL test passes when the program refuses (non-zero exit), as in CTest,
        # but never when valgrind itself reports an error (its own exit code, 99).
        ok = (r.returncode not in (0, 99)) if will_fail else (r.returncode == 0)
        return name, r.returncode, ok, r.stdout, time.time() - start

    failed, ran = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for name, code, ok, output, secs in pool.map(run, jobs):
            ran += 1
            status = ("ok" if code == 0 else "ok (refused as expected, exit %d)" % code) if ok                 else "FAILED (exit %d)" % code
            if not ok or args.verbose:
                sys.stdout.write(output)
            print("%-40s %s  %.1fs" % (name, status, secs), flush=True)
            if not ok:
                failed.append(name)

    print("not run under valgrind (script tests): %s" % (", ".join(skipped) or "none"))
    if failed:
        print("FAIL: %d of %d tests failed under valgrind: %s" % (len(failed), ran, ", ".join(failed)))
        return 1
    if ran == 0:
        print("FAIL: no tests matched")
        return 1
    print("PASS: %d tests clean under valgrind" % ran)
    return 0


if __name__ == "__main__":
    sys.exit(main())
