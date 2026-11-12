#!/usr/bin/env python3
"""Run the compiled CTest tests of a build under valgrind's memcheck.

    python -I tools/valgrind-tests.py BUILD_DIR [--exclude REGEX] [--include REGEX]

Asks CTest for the registered tests (ctest --show-only=json-v1) and runs each
one whose command is a program built in BUILD_DIR, with the same arguments and
working directory, under

    valgrind --error-exitcode=99 --leak-check=full --errors-for-leak-kinds=definite
             --track-origins=yes --quiet

Tests run through sh or python (the isolation checks, the tool scripts) are
left out: valgrind would check the shell, not our code. A test fails if it
fails on its own or if valgrind reports a memory error or a definite leak.
Exits 1 if any test failed. Standard library only.
"""
import argparse
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
    args = ap.parse_args()
    build = os.path.abspath(args.build)

    info = json.loads(subprocess.run(
        ["ctest", "--test-dir", build, "--show-only=json-v1"],
        check=True, capture_output=True, text=True).stdout)

    failed, ran, skipped = [], 0, []
    for t in info.get("tests", []):
        name, cmd = t["name"], t.get("command") or []
        if args.include and not re.search(args.include, name):
            continue
        if args.exclude and re.search(args.exclude, name):
            continue
        if not cmd or not os.path.abspath(cmd[0]).startswith(build + os.sep):
            skipped.append(name)
            continue
        cwd = build
        for p in t.get("properties", []):
            if p.get("name") == "WORKING_DIRECTORY":
                cwd = p["value"]
        start = time.time()
        r = subprocess.run(VALGRIND + cmd, cwd=cwd)
        ran += 1
        status = "ok" if r.returncode == 0 else "FAILED (exit %d)" % r.returncode
        print("%-40s %s  %.1fs" % (name, status, time.time() - start), flush=True)
        if r.returncode != 0:
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
