#!/usr/bin/env python3
"""Mutation run for the composite node (core/node): the router and the
hand-off brackets (engineering checklist item 8).

Each line of tests/node/mutants.txt is a deliberate small fault:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
OLD must occur exactly once in FILE, or N says which occurrence (1-based).
In OLD and NEW, \\n is a newline and \\\\ a backslash.

The repository's tracked files are copied to WORK/src once and configured in
WORK/build (Release). For each mutant the one file is changed, the node's
unit tests are rebuilt incrementally and run, and the file is restored. A
mutant that no test notices is a survivor; one that does not compile is
reported apart. The source tree is never written. A survivor the list names
in a line "# equivalent NAME: why" has been triaged; the run exits 1 if any
survivor is not triaged, or any mutant does not apply or compile.

usage: tools/mutate-node.py SOURCE-DIR WORK-DIR [-j N] [NAME...]
"""
import os
import shutil
import subprocess
import sys
import time

TESTS = ["node", "node_route", "node_timers", "node_handoff", "node_sizing", "node_hostile", "node_release", "action"]
TARGETS = ["test_" + t for t in TESTS]


def unescape(text):
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            out.append("\n" if text[i + 1] == "n" else text[i + 1])
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def load(path):
    mutants, triaged = [], {}
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if line.startswith("# equivalent ") and ":" in line:
                name, why = line[len("# equivalent "):].split(":", 1)
                triaged[name.strip()] = why.strip()
                continue
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) not in (4, 5):
                sys.exit("%s:%d: expected 4 or 5 tab-separated fields" % (path, no))
            nth = int(parts[4]) if len(parts) == 5 else 0
            mutants.append((parts[0], parts[1], unescape(parts[2]), unescape(parts[3]), nth))
    return mutants, triaged


def replaced(text, old, new, nth):
    count = text.count(old)
    if nth == 0:
        if count != 1:
            return None, "occurs %d times" % count
        return text.replace(old, new, 1), None
    if count < nth:
        return None, "occurs %d times, wanted occurrence %d" % (count, nth)
    at = -1
    for _ in range(nth):
        at = text.index(old, at + 1)
    return text[:at] + new + text[at + len(old):], None


def run(cmd, cwd=None, timeout=600):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def main():
    args = sys.argv[1:]
    jobs = "4"
    if "-j" in args:
        i = args.index("-j")
        jobs = args[i + 1]
        del args[i:i + 2]
    if len(args) < 2:
        sys.exit(__doc__)
    source, work, only = os.path.abspath(args[0]), os.path.abspath(args[1]), set(args[2:])
    src, build = os.path.join(work, "src"), os.path.join(work, "build")
    mutants, triaged = load(os.path.join(source, "tests/node/mutants.txt"))
    if only:
        mutants = [m for m in mutants if m[0] in only]
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    code, files = run(["git", "ls-files", "-co", "--exclude-standard"], cwd=source)
    for rel in files.splitlines():
        if os.path.isfile(os.path.join(source, rel)):
            os.makedirs(os.path.dirname(os.path.join(src, rel)) or src, exist_ok=True)
            shutil.copy2(os.path.join(source, rel), os.path.join(src, rel))
    if not os.path.exists(os.path.join(build, "CMakeCache.txt")):
        code, out = run(["cmake", "-S", src, "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DGZ_VALGRIND_TESTS=OFF",
                         "-DGZ_MUTATION_BUILD=ON"])
        if code:
            sys.exit("configure failed:\n" + out[-3000:])
    make = ["cmake", "--build", build, "-j", jobs, "--target"] + TARGETS
    code, out = run(make, timeout=3600)
    if code:
        sys.exit("the unmutated tree does not build:\n" + out[-3000:])
    for t in TESTS:
        code, out = run([os.path.join(build, "test_" + t)])
        if code:
            sys.exit("the unmutated tree fails test %s:\n%s" % (t, out[-2000:]))
    killed, survivors, broken = [], [], []
    start = time.time()
    for name, rel, old, new, nth in mutants:
        path = os.path.join(src, rel)
        with open(path, encoding="utf-8") as f:
            original = f.read()
        text, why = replaced(original, old, new, nth)
        if text is None:
            broken.append((name, "does not apply: " + why))
            print("BROKEN   %s (%s)" % (name, why), flush=True)
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        try:
            code, out = run(make, timeout=1800)
            if code:
                broken.append((name, "does not compile"))
                errors = [line for line in out.splitlines() if "error" in line][:3]
                print("NOBUILD  %s" % name, flush=True)
                for line in errors:
                    print("         " + line, flush=True)
                continue
            by = None
            for t in TESTS:
                code, out = run([os.path.join(build, "test_" + t)], timeout=300)
                if code:
                    by = t
                    break
            if by:
                killed.append((name, by))
                print("killed   %s (by %s)" % (name, by), flush=True)
            else:
                survivors.append(name)
                print("SURVIVED %s%s" % (name, " (triaged: %s)" % triaged[name] if name in triaged else ""), flush=True)
        finally:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(original)
    run(make, timeout=1800)
    untriaged = [s for s in survivors if s not in triaged]
    print("mutants %d: killed %d, survived %d (triaged %d), not applied or not compiled %d, %.0f s"
          % (len(mutants), len(killed), len(survivors), len(survivors) - len(untriaged), len(broken),
             time.time() - start))
    return 1 if untriaged or broken else 0


if __name__ == "__main__":
    sys.exit(main())
