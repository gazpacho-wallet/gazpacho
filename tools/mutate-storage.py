#!/usr/bin/env python3
"""Mutation run for ports/storage/crypto (engineering checklist item 8).

Each line of ports/storage/crypto/tests/mutants.txt is a deliberate small fault:
    NAME <tab> FILE <tab> OLD <tab> NEW [<tab> N]
(three fields: NEW is empty, the mutant deletes OLD). FILE is relative to ports/storage/crypto. OLD must occur exactly once, or N
says which occurrence (1-based); \\n in OLD or NEW is a newline, \\t a tab.
Lines starting with # are comments. Each mutant is applied to a scratch copy
(never to the source tree); the storage library (test and release builds),
the helpers and every storage test are compiled there against the libsodium
and utf8proc of BUILD-DIR, and every test runs (the constant-time test under
valgrind when it is installed). A mutant that no test notices is a survivor;
a mutant that does not compile is reported apart (it proves nothing).
Survivors are triaged in docs/notes/storage-crypto.md.

usage: tools/mutate-storage.py SOURCE-DIR BUILD-DIR [NAME...]
Standard library only.
"""
import os
import shutil
import subprocess
import sys
import tempfile

LIB = ["sc_core.c", "sc_keyfile.c", "sc_journal.c", "sc_export.c", "sc_misc.c", "sc_pass.c",
       "sc_wordlist.c", "sc_kdf.c", "sc_files.c"]
TESTS = [  # name, sources, arguments, test library (True) or release (False)
    ("vectors", ["tests/test_vectors.c", "tests/sc_test.c"], [], True),
    ("formats", ["tests/test_formats.c", "tests/sc_test.c"], [], True),
    ("files", ["tests/test_files.c", "tests/sc_test.c"], [], True),
    ("release", ["tests/test_release.c"], [], False),
    ("fuzz_keyfile", ["tests/fuzz_sc_keyfile.c", "tests/fuzz_main.c"], ["4000"], True),
    ("fuzz_frame", ["tests/fuzz_sc_frame.c", "tests/fuzz_main.c"], ["4000"], True),
    ("fuzz_mark", ["tests/fuzz_sc_mark.c", "tests/fuzz_main.c"], ["4000"], True),
    ("fuzz_export", ["tests/fuzz_sc_export.c", "tests/fuzz_main.c"], ["4000"], True),
]


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


def apply(path, old, new, nth):
    with open(path) as f:
        text = f.read()
    count = text.count(old)
    if nth is None and count != 1:
        return "OLD occurs %d times" % count
    if nth is not None and count < nth:
        return "OLD occurs %d times, wanted occurrence %d" % (count, nth)
    pos = -1
    for _ in range(nth or 1):
        pos = text.index(old, pos + 1)
    with open(path, "w") as f:
        f.write(text[:pos] + new + text[pos + len(old):])
    return None


def cc(args, cwd):
    r = subprocess.run(["cc", "-std=gnu11", "-O1", "-g0", "-w"] + args, cwd=cwd, capture_output=True, text=True)
    return r.returncode == 0, r.stderr[-2000:]


def build_and_test(work, deps):
    inc = ["-I", "include", "-I", ".", "-I", deps["sodium_inc"], "-I", deps["u8_inc"], "-DUTF8PROC_STATIC"]
    libs = [deps["sodium_lib"], deps["u8_lib"]]
    objs = {}
    for flavour, defs in (("test", ["-DGZ_SC_TEST_ENTRY"]), ("rel", []), ("ctime", ["-DGZ_SC_TEST_ENTRY", "-DGZ_SC_CTIME"])):
        if flavour == "ctime" and not deps["valgrind"]:
            continue
        objs[flavour] = []
        for src in LIB:
            obj = "%s_%s.o" % (flavour, src[:-2])
            ok, err = cc(["-c", src, "-o", obj] + inc + defs, work)
            if not ok:
                return "compile", err
            objs[flavour].append(obj)
    ok, err = cc(["tests/kdf_helper.c", "-o", "sc_kdf_helper", "-DGZ_SC_TEST_ENTRY"] + inc + objs["test"] + libs, work)
    if not ok:
        return "compile", err
    ok, err = cc(["tests/bad_helper.c", "-o", "sc_bad_helper"], work)
    if not ok:
        return "compile", err
    helper = os.path.join(work, "sc_kdf_helper")
    bad = os.path.join(work, "sc_bad_helper")
    for name, srcs, args, testlib in TESTS:
        flags = ["-DGZ_SC_TEST_ENTRY"] if testlib else []
        defs = ['-DGZ_SC_HELPER="%s"' % helper, '-DGZ_SC_BAD_HELPER="%s"' % bad]
        ok, err = cc(srcs + ["-o", "t_" + name] + inc + flags + defs + objs["test" if testlib else "rel"] + libs, work)
        if not ok:
            return "compile", err
        try:
            r = subprocess.run([os.path.join(work, "t_" + name)] + args, cwd=work, capture_output=True,
                               text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return "killed", "%s: timeout" % name
        if r.returncode != 0:
            return "killed", "%s: %s" % (name, (r.stderr or r.stdout)[-300:])
    if deps["valgrind"]:
        ok, err = cc(["tests/test_ctime.c", "-o", "t_ctime", "-DGZ_SC_TEST_ENTRY", "-DGZ_SC_CTIME"] + inc +
                     objs["ctime"] + libs, work)
        if not ok:
            return "compile", err
        r = subprocess.run(["valgrind", "--error-exitcode=42", "--suppressions=tests/ctime.supp", "--quiet",
                            "./t_ctime"], cwd=work, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            return "killed", "ctime: %s" % r.stderr[-300:]
    return "survived", ""


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    src = os.path.abspath(os.path.join(sys.argv[1], "ports", "storage", "crypto"))
    build = os.path.abspath(sys.argv[2])
    only = set(sys.argv[3:])
    deps = {
        "sodium_inc": os.path.join(build, "libsodium", "include"),
        "sodium_lib": os.path.join(build, "libsodium", "lib", "libsodium.a"),
        "u8_inc": os.path.join(build, "_deps", "utf8proc-src"),
        "u8_lib": os.path.join(build, "_deps", "utf8proc-build", "libutf8proc.a"),
        "valgrind": shutil.which("valgrind") is not None,
    }
    for k in ("sodium_lib", "u8_lib"):
        if not os.path.exists(deps[k]):
            print("FAIL: %s not found; build BUILD-DIR first" % deps[k])
            return 2
    mutants = []
    with open(os.path.join(src, "tests", "mutants.txt")) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) == 3:  # NEW empty: the mutant deletes OLD
                parts.append("")
            if len(parts) not in (4, 5):
                print("FAIL: malformed line: %r" % line)
                return 2
            name, fname, old, new = parts[:4]
            nth = int(parts[4]) if len(parts) == 5 else None
            if not only or name in only:
                mutants.append((name, fname, unescape(old), unescape(new), nth))
    work_root = tempfile.mkdtemp(prefix="gz-mutate-storage-")
    results = {"killed": [], "survived": [], "compile": [], "invalid": []}
    try:
        base = os.path.join(work_root, "base")
        shutil.copytree(src, base)
        status, err = build_and_test(base, deps)
        if status != "survived":
            print("FAIL: the unmutated code does not pass (%s): %s" % (status, err))
            return 1
        for name, fname, old, new, nth in mutants:
            work = os.path.join(work_root, "m")
            shutil.rmtree(work, ignore_errors=True)
            shutil.copytree(src, work)
            problem = apply(os.path.join(work, fname), old, new, nth)
            if problem:
                results["invalid"].append(name)
                print("INVALID  %-34s %s" % (name, problem), flush=True)
                continue
            status, err = build_and_test(work, deps)
            results[status].append(name)
            print("%-8s %-34s %s" % (status.upper(), name, err.splitlines()[0] if err else ""), flush=True)
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
    total = len(mutants) - len(results["invalid"]) - len(results["compile"])
    print("\n%d mutants: %d killed, %d survived, %d did not compile, %d invalid" % (
        len(mutants), len(results["killed"]), len(results["survived"]), len(results["compile"]),
        len(results["invalid"])))
    if total:
        print("score: %.1f%% of compiling mutants killed" % (100.0 * len(results["killed"]) / total))
    if results["survived"]:
        print("survivors: " + ", ".join(results["survived"]))
    return 1 if results["invalid"] or results["compile"] else 0


if __name__ == "__main__":
    sys.exit(main())
