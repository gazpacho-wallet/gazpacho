#!/usr/bin/env python3
"""Mutation run for signer/ and the two S1 checks (docs/notes/signer.md 8).

Each line of signer/tests/mutants.txt is a deliberate small fault, one per
check:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
OLD must occur exactly once in FILE, or N says which occurrence (1-based).
In OLD and NEW, \\n is a newline, \\t a tab and \\\\ a backslash.

The repository's tracked files are copied to WORK/src once. A mutant of a
file under signer/ rebuilds test_signer and test_signer_vectors incrementally in WORK/build
(configured once, Release, GZ_MUTATION_BUILD) and runs both; a mutant of a file under tools/ runs
that tool's own test (tests/tools/test_check_*.py) on the copy. The file is
restored after each. A mutant that no test notices is a survivor; one that
does not compile is reported apart. A survivor the list names in a line
"# equivalent NAME: why" has been triaged; the run exits 1 if any survivor is
not triaged, or any mutant does not apply or compile.

usage: tools/mutate-signer.py SOURCE-DIR WORK-DIR [-j N] [NAME...]
"""
import os
import shutil
import subprocess
import sys

TOOL_TESTS = {
    "tools/check-tags.py": "tests/tools/test_check_tags.py",
    "tools/check-signer-boundary.sh": "tests/tools/test_check_signer_boundary.py",
}


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


def load(path):
    mutants, triaged = [], {}
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if line.startswith("# equivalent "):
                name, _, why = line[len("# equivalent "):].partition(":")
                triaged[name.strip()] = why.strip()
                continue
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) not in (4, 5):
                sys.exit("%s:%d: want NAME, FILE, OLD, NEW [, N]" % (path, no))
            mutants.append((parts[0], parts[1], unescape(parts[2]), unescape(parts[3]),
                            int(parts[4]) if len(parts) == 5 else 0))
    return mutants, triaged


def apply(text, old, new, n):
    count = text.count(old)
    if n == 0:
        if count != 1:
            return None
        return text.replace(old, new, 1)
    if n > count:
        return None
    at = -1
    for _ in range(n):
        at = text.find(old, at + 1)
    return text[:at] + new + text[at + len(old):]


def main(argv):
    jobs = "4"
    if "-j" in argv:
        k = argv.index("-j")
        jobs = argv[k + 1]
        del argv[k:k + 2]
    if len(argv) < 2:
        sys.exit(__doc__)
    source, work = os.path.abspath(argv[0]), os.path.abspath(argv[1])
    only = set(argv[2:])
    src, build = os.path.join(work, "src"), os.path.join(work, "build")
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(src)
    files = subprocess.run(["git", "-C", source, "ls-files", "-z"], capture_output=True, check=True).stdout
    for rel in files.decode().split("\0"):
        if not rel or os.path.islink(os.path.join(source, rel)):
            continue
        dest = os.path.join(src, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(os.path.join(source, rel), dest)
    mutants, triaged = load(os.path.join(src, "signer", "tests", "mutants.txt"))
    if only:
        mutants = [m for m in mutants if m[0] in only]
    need_build = any(m[1].startswith("signer/") for m in mutants)
    # The production library's test and the vectors build's: a mutant is
    # killed if either fails.
    vectors = os.path.join(src, "signer", "tests", "vectors.txt")
    signer_tests = [[os.path.join(build, "signer", t), vectors] for t in ("test_signer", "test_signer_vectors")]
    targets = ["--target", "test_signer", "--target", "test_signer_vectors"]
    if need_build:
        # GZ_MUTATION_BUILD: a variable a fault leaves unused must not stop the build.
        subprocess.run(["cmake", "-S", src, "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DGZW_BREAK_CHECKS=OFF",
                        "-DGZ_VALGRIND_TESTS=OFF", "-DGZ_MUTATION_BUILD=ON"], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["cmake", "--build", build] + targets + ["-j", jobs], check=True, stdout=subprocess.DEVNULL)
        for t in signer_tests:
            r = subprocess.run(t, capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit("%s fails before any mutant:\n%s" % (t[0], r.stdout))
    for tool, test in TOOL_TESTS.items():
        if any(m[1] == tool for m in mutants):
            r = subprocess.run([sys.executable, "-I", os.path.join(src, test)], capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit("%s fails before any mutant:\n%s" % (test, r.stdout))

    killed, survived, bad = [], [], []
    for name, rel, old, new, n in mutants:
        path = os.path.join(src, rel)
        with open(path, encoding="utf-8") as f:
            original = f.read()
        changed = apply(original, old, new, n)
        if changed is None:
            bad.append((name, "does not apply"))
            print("BAD      %s (does not apply)" % name)
            continue
        with open(path, "w", encoding="utf-8") as f:
            f.write(changed)
        try:
            if rel.startswith("signer/"):
                b = subprocess.run(["cmake", "--build", build] + targets + ["-j", jobs],
                                   capture_output=True, text=True)
                if b.returncode != 0:
                    bad.append((name, "does not compile"))
                    print("BAD      %s (does not compile)" % name)
                    print(b.stdout[-2000:])
                    continue
                cmds = signer_tests
            elif rel in TOOL_TESTS:
                cmds = [[sys.executable, "-I", os.path.join(src, TOOL_TESTS[rel])]]
            else:
                bad.append((name, "no test for " + rel))
                print("BAD      %s (no test for %s)" % (name, rel))
                continue
            dead = False
            for cmd in cmds:
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                    dead = dead or r.returncode != 0
                except subprocess.TimeoutExpired:
                    dead = True
            if dead:
                killed.append(name)
                print("killed   %s" % name)
            elif name in triaged:
                print("triaged  %s (%s)" % (name, triaged[name]))
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
    print("%d mutants: %d killed, %d survived untriaged, %d triaged, %d bad" %
          (len(mutants), len(killed), len(survived), len(mutants) - len(killed) - len(survived) - len(bad), len(bad)))
    return 1 if survived or bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
