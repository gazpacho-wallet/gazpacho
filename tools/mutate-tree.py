#!/usr/bin/env python3
"""Mutation run for core/tree (engineering checklist item 8).

Each line of tests/tree/mutants.txt is a deliberate small fault:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
OLD must occur exactly once in FILE, or N says which occurrence (1-based).
In OLD and NEW, \\n is a newline and \\\\ a backslash.

The repository's tracked files are copied to WORK/src once and configured in
WORK/build (Release). For each mutant the one file is changed, the tree's
tests are rebuilt incrementally and run, and the file is restored. A mutant
that no test notices is a survivor; one that does not compile is reported
apart (it says nothing about the tests). The source tree is never written.
A survivor the list names in a line "# equivalent NAME: why" has been
triaged (an equivalent or unreachable fault, with the reason); the run exits
1 if any survivor is not triaged, any mutant does not apply or compile.

usage: tools/mutate-tree.py SOURCE-DIR WORK-DIR [-j N] [NAME...]
"""
import os
import shutil
import subprocess
import sys
import time

TARGETS = ["test_tree_terms", "test_tree_exit", "test_tree_build", "test_tree_checks", "tree_model_driver",
           "fuzz_tree_terms", "fuzz_tree_tx", "gazpacho_tree"]


def tests(src, build):
    t = os.path.join(build, "core", "tree")
    return [
        ("terms", [os.path.join(t, "test_tree_terms")]),
        ("exit", [os.path.join(t, "test_tree_exit")]),
        ("build", [os.path.join(t, "test_tree_build"), os.path.join(src, "tests/reference/tree-from-terms-txids.txt")]),
        ("checks", [os.path.join(t, "test_tree_checks")]),
        ("model", [sys.executable, "-I", os.path.join(src, "tests/tree/model_check.py"), os.path.join(t, "tree_model_driver"),
                   os.path.join(src, "tools/spec-vectors.py"), "500", "7"]),
        ("fuzz_terms", [os.path.join(t, "fuzz_tree_terms"), "20000"]),
        ("fuzz_tx", [os.path.join(t, "fuzz_tree_tx"), "20000"]),
        ("isolation", ["sh", os.path.join(src, "tools/check-core-isolation.sh"), os.path.join(t, "libgazpacho_tree.a")]),
    ]


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
                sys.exit(f"{path}:{no}: expected 4 or 5 tab-separated fields")
            nth = int(parts[4]) if len(parts) == 5 else 0
            mutants.append((parts[0], parts[1], unescape(parts[2]), unescape(parts[3]), nth))
    return mutants, triaged


def replaced(text, old, new, nth):
    count = text.count(old)
    if nth == 0:
        if count != 1:
            return None, f"occurs {count} times"
        return text.replace(old, new, 1), None
    if count < nth:
        return None, f"occurs {count} times, wanted occurrence {nth}"
    at = -1
    for _ in range(nth):
        at = text.index(old, at + 1)
    return text[:at] + new + text[at + len(old):], None


def run(cmd, cwd=None, timeout=600):
    try:
        p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        return p.returncode, p.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -9, "timeout"


def main():
    args = sys.argv[1:]
    jobs = "2"
    if "-j" in args:
        k = args.index("-j")
        jobs = args[k + 1]
        del args[k:k + 2]
    if len(args) < 2:
        sys.exit(__doc__)
    source, work = os.path.abspath(args[0]), os.path.abspath(args[1])
    names = set(args[2:])
    src, build = os.path.join(work, "src"), os.path.join(work, "build")
    mutants, triaged = load(os.path.join(source, "tests/tree/mutants.txt"))
    if names:
        mutants = [m for m in mutants if m[0] in names]

    files = subprocess.run(["git", "-C", source, "ls-files", "-co", "--exclude-standard"], stdout=subprocess.PIPE,
                           check=True).stdout.decode().split("\n")
    if os.path.isdir(src):
        shutil.rmtree(src)
    for rel in files:
        if not rel:
            continue
        a, b = os.path.join(source, rel), os.path.join(src, rel)
        if os.path.isfile(a):
            os.makedirs(os.path.dirname(b), exist_ok=True)
            shutil.copy(a, b)   # a new mtime: an old build directory is rebuilt, never trusted
    if not os.path.isdir(build):
        rc, out = run(["cmake", "-S", src, "-B", build, "-DCMAKE_BUILD_TYPE=Release"])
        if rc:
            sys.exit("configure failed:\n" + out[-3000:])

    def build_all():
        return run(["cmake", "--build", build, "-j", jobs, "--target"] + TARGETS)

    def run_tests():
        for name, cmd in tests(src, build):
            rc, out = run(cmd, timeout=300)
            if rc != 0:
                return name
        return None

    rc, out = build_all()
    if rc:
        sys.exit("baseline build failed:\n" + out[-3000:])
    failed = run_tests()
    if failed:
        sys.exit(f"baseline: test {failed} fails without any mutant")

    killed, survived, stillborn, bad = [], [], [], []
    start = time.time()
    for name, rel, old, new, nth in mutants:
        path = os.path.join(src, rel)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        mutated, why = replaced(text, old, new, nth)
        if mutated is None:
            bad.append((name, why))
            print(f"BAD       {name}: {why}", flush=True)
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(mutated)
        try:
            rc, out = build_all()
            if rc:
                stillborn.append(name)
                print(f"NO BUILD  {name}", flush=True)
                continue
            by = run_tests()
            if by:
                killed.append((name, by))
                print(f"killed    {name} (by {by})", flush=True)
            else:
                survived.append(name)
                print(f"SURVIVED  {name}", flush=True)
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            os.utime(path, None)
    build_all()
    total = len(killed) + len(survived)
    print(f"\n{len(mutants)} mutants: {len(killed)} killed, {len(survived)} survived, "
          f"{len(stillborn)} did not compile, {len(bad)} not applicable; {time.time() - start:.0f} s")
    for s in survived:
        print(("  survivor (triaged: %s): %s" % (triaged[s], s)) if s in triaged else "  SURVIVOR, NOT TRIAGED: " + s)
    for b, why in bad:
        print(f"  not applicable: {b} ({why})")
    untriaged = [s for s in survived if s not in triaged]
    return 1 if untriaged or bad or stillborn else 0


if __name__ == "__main__":
    sys.exit(main())
