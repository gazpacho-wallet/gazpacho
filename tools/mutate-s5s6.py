#!/usr/bin/env python3
"""Mutation run for the S5/S6 program code (branch s5-s6-program).

Each line of tools/mutants-s5s6.txt is one small fault in the new code:
    NAME <tab> FILE <tab> OLD <tab> NEW
(FILE relative to the source tree; OLD must occur exactly once; \\n is a
newline). Each mutant is applied to a scratch copy of SOURCE-DIR, built in a
scratch build tree (configured like BUILD-DIR), and the tests that cover the
new code run: the sealed journal fuzzer, the start counter fuzzer, the
journal and storage tests, and the program's storage tests. A mutant that no
test notices survived; one that does not compile is reported apart.

    python3 tools/mutate-s5s6.py SOURCE-DIR BUILD-DIR WORK-DIR [NAME...]

Writes WORK-DIR/results.txt. Standard library only.
"""
import os
import shutil
import subprocess
import sys

SRC, BUILD, WORK = (os.path.abspath(a) for a in sys.argv[1:4])
ONLY = set(sys.argv[4:])
TESTS = ("journal_fuzz_sealed|storage_fuzz_sc_counter|^journal$|^journal_restore$|storage_files|"
         "program_unlock|program_storage_damage|program_journal_restore")


def unescape(t):
    return t.replace("\\n", "\n").replace("\\t", "\t")


def run(cmd, cwd, timeout):
    try:
        r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return r.returncode, r.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -1, "timeout"


def main():
    mutants = []
    for line in open(os.path.join(SRC, "tools/mutants-s5s6.txt")):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        name, path, old, new = f[0], f[1], unescape(f[2]), unescape(f[3]) if len(f) > 3 else ""
        if not ONLY or name in ONLY:
            mutants.append((name, path, old, new))
    os.makedirs(WORK, exist_ok=True)
    src = os.path.join(WORK, "src")
    bld = os.path.join(WORK, "build")
    if os.path.exists(src):
        shutil.rmtree(src)
    shutil.copytree(SRC, src, ignore=shutil.ignore_patterns(".git", "build*"))
    cache = open(os.path.join(BUILD, "CMakeCache.txt")).read()
    btype = [l.split("=", 1)[1] for l in cache.splitlines() if l.startswith("CMAKE_BUILD_TYPE:")][0]
    deps = [l.split("=", 1)[1] for l in cache.splitlines() if l.startswith("GZ_DEPS_DIR:")]
    cfg = ["cmake", "-S", src, "-B", bld, "-DCMAKE_BUILD_TYPE=" + btype]
    if deps and deps[0]:
        cfg.append("-DGZ_DEPS_DIR=" + deps[0])
    if not os.path.exists(bld):
        code, out = run(cfg, WORK, 1800)
        if code:
            print(out)
            return 2
        code, out = run(["nice", "-n", "15", "cmake", "--build", bld, "-j3"], WORK, 7200)
        if code:
            print(out[-3000:])
            return 2
    results = []
    for name, path, old, new in mutants:
        target = os.path.join(src, path)
        text = open(target).read()
        if text.count(old) != 1:
            results.append((name, "BAD-MUTANT (%d matches)" % text.count(old)))
            continue
        open(target, "w").write(text.replace(old, new))
        try:
            code, out = run(["nice", "-n", "15", "cmake", "--build", bld, "-j3"], WORK, 3600)
            if code:
                results.append((name, "does-not-compile"))
                continue
            code, out = run(["nice", "-n", "15", "ctest", "-j2", "-R", TESTS, "--timeout", "900",
                             "--stop-on-failure"], bld, 7200)
            killer = ""
            for l in out.splitlines():
                if "***Failed" in l or "***Timeout" in l or "Exception" in l:
                    killer = l.split(":")[1].split()[0] if ":" in l else l
                    break
            results.append((name, ("killed by " + killer) if code else "SURVIVED"))
        finally:
            open(target, "w").write(text)
        with open(os.path.join(WORK, "results.txt"), "w") as f:
            for n, r in results:
                f.write("%s\t%s\n" % (n, r))
        print(name, results[-1][1], flush=True)
    # Back to the unmutated build.
    run(["nice", "-n", "15", "cmake", "--build", bld, "-j3"], WORK, 3600)
    surv = [n for n, r in results if r == "SURVIVED"]
    print("%d mutants, %d survived: %s" % (len(results), len(surv), " ".join(surv)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
