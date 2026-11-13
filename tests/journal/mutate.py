"""Mutation testing of ports/storage/journal.c.

Makes one small change at a time (a comparison, a logical operator, + or -,
a constant, a negation, a return value, a deleted statement), rebuilds the
journal's tests and the gz-journal tool against the mutant, and runs, in this
order, test_journal, test_journal_review, the cross-check against the independent reader (2,000
journals), the fuzzer (20,000 inputs) and the crash sweeps. A mutant is killed
by the first that fails or times out. Each one that passes them all is then
built again with AddressSanitizer, UBSan and leak detection and run through
test_journal, test_journal_edges, test_journal_restore, test_journal_review, the fuzzer (3,000 inputs) and the crash
sweeps: that stage sees what the plain tests cannot, such as a deleted free
or a read one byte past a buffer. A mutant that passes both survived. Each
test runs in its own process group, killed whole on timeout.

    python3 mutate.py SOURCE_DIR BUILD_DIR WORK_DIR [JOBS]

BUILD_DIR is a configured and built release tree (its static libraries are
linked in). Writes WORK_DIR/results.txt and prints the survivors.
"""
import concurrent.futures
import os
import re
import signal
import subprocess
import sys

SRC, BUILD, WORK = (os.path.abspath(a) for a in sys.argv[1:4])
JOBS = int(sys.argv[4]) if len(sys.argv) > 4 else 4
JOURNAL = os.path.join(SRC, "ports/storage/journal.c")
CFLAGS = ["-std=gnu11", "-O1", "-w",
          "-I" + os.path.join(SRC, "core/gazpacho/include"),
          "-I" + os.path.join(SRC, "ports/storage"),
          "-I" + os.path.join(SRC, "core/superscalar/include")]
SAN = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined", "-g"]
SAN_TESTS = [("test_journal", [], 300), ("test_journal_edges", [], 300), ("test_journal_restore", [], 300),
             ("test_journal_review", [], 300), ("test_journal_review_b", [], 300), ("test_journal_fuzz", ["3000", "5"], 300),
             ("test_journal_crash", [], 600)]
TESTS = [("test_journal", [], 120),
         ("test_journal_edges", [], 120),
         ("test_journal_restore", [], 120),
         ("test_journal_review", [], 120),
         ("test_journal_review_b", [], 120),
         ("crosscheck", None, 120),
         ("test_journal_fuzz", ["20000", "5"], 120),
         ("test_journal_crash", [], 240)]


def libs():
    found = {}
    for root, _, files in os.walk(BUILD):
        for f in files:
            if f in ("libgazpacho_core.a", "libgazpacho_superscalar.a", "libsecp256k1.a"):
                found[f] = os.path.join(root, f)
    return [found["libgazpacho_core.a"], found["libgazpacho_superscalar.a"],
            found["libsecp256k1.a"], "-lcrypto"]


def code_lines(text):
    """Line numbers outside comments and preprocessor lines."""
    out, in_comment = [], False
    for i, line in enumerate(text.split("\n")):
        s = line.strip()
        if in_comment:
            if "*/" in s:
                in_comment = False
            continue
        if s.startswith("/*"):
            in_comment = "*/" not in s
            continue
        if not s or s.startswith("#") or s.startswith("*"):
            continue
        out.append(i)
    return out


SUBS = [(r"==", "!="), (r"!=", "=="), (r"(?<![<-])<=", "<"), (r"(?<![<-])<(?![<=])", "<="),
        (r"(?<![->])>=", ">"), (r"(?<![->])>(?![>=])", ">="), (r"&&", "||"), (r"\|\|", "&&"),
        (r" \+ ", " - "), (r" - ", " + "), (r"\+\+", "--"), (r"if \(!", "if ("),
        (r"return 0;", "return 1;"), (r"return 1;", "return 0;")]
DECL = re.compile(r"^\s*(static|const|uint|int |long |size_t|gz_|char|entry_t|collect_t|pending_t|struct|typedef|return|if|for|while|else|case|default|switch|\}|\{)")


def mutants(text):
    lines = text.split("\n")
    for i in code_lines(text):
        line = lines[i]
        code = line.split("/*")[0]
        for pat, rep in SUBS:
            for m in re.finditer(pat, code):
                yield i, line[:m.start()] + rep + line[m.end():]
        for m in re.finditer(r"(?<![\w.])(0x[0-9a-fA-F]+|\d+)(u|ull|ULL)?(?![\w.])", code):
            t = m.group(1)
            if len(t) > 1 and t[0] == "0" and t[1] not in "xX":
                new = "0%o" % (int(t, 8) + 1)
            else:
                new = str(int(t, 0) + 1)
            yield i, line[:m.start()] + new + (m.group(2) or "") + line[m.end():]
        s = code.strip()
        if s.endswith(";") and not DECL.match(code):
            yield i, re.sub(r"\S.*", ";", line, count=1)


def run(cmd, timeout, cwd, leaks):
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=%d" % leaks)
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, env=env)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        return "timeout"


def check(job):
    n, lineno, new_line, text, objs, linkargs = job[:6]
    san = len(job) > 6
    flags, tests = (CFLAGS + SAN, SAN_TESTS) if san else (CFLAGS, TESTS)
    d = os.path.join(WORK, ("s%04d" if san else "m%04d") % n)
    os.makedirs(d, exist_ok=True)
    lines = text.split("\n")
    lines[lineno] = new_line
    src = os.path.join(d, "journal.c")
    with open(src, "w") as f:
        f.write("\n".join(lines))
    obj = os.path.join(d, "journal.o")
    if subprocess.run(["gcc", *flags, "-c", src, "-o", obj], capture_output=True).returncode:
        return n, lineno, new_line, "build-error"
    for name, o in objs.items():
        r = subprocess.run(["gcc", *(SAN if san else []), "-o", os.path.join(d, name), *o, obj, *linkargs],
                           capture_output=True)
        if r.returncode:
            return n, lineno, new_line, "build-error"
    for name, args, timeout in tests:
        if name == "crosscheck":
            cmd = [sys.executable, os.path.join(SRC, "tests/journal/crosscheck.py"),
                   os.path.join(d, "gz-journal"), "2000", "3"]
        else:
            cmd = [os.path.join(d, name), *args]
        r = run(cmd, timeout, d, 1)
        if r != 0:
            subprocess.run(["rm", "-rf", d])
            return n, lineno, new_line, "killed by %s%s%s" % ("sanitizers in " if san else "", name,
                                                              " (timeout)" if r == "timeout" else "")
    subprocess.run(["rm", "-rf", d])
    return n, lineno, new_line, "SURVIVED"


def common_objects(name, flags):
    common = os.path.join(WORK, name)
    os.makedirs(common, exist_ok=True)
    objs = {}
    t = os.path.join(SRC, "tests/journal")
    memfs = os.path.join(common, "memfs.o")
    subprocess.run(["gcc", *flags, "-c", os.path.join(t, "memfs.c"), "-o", memfs], check=True)
    for name, srcf in [("test_journal", "test_journal.c"), ("test_journal_crash", "test_journal_crash.c"),
                       ("test_journal_fuzz", "test_journal_fuzz.c"), ("test_journal_edges", "test_journal_edges.c"),
                       ("test_journal_restore", "test_journal_restore.c"),
                       ("test_journal_review", "test_journal_review.c"),
                       ("test_journal_review_b", "test_journal_review_b.c")]:
        o = os.path.join(common, name + ".o")
        subprocess.run(["gcc", *flags, "-c", os.path.join(t, srcf), "-o", o], check=True)
        objs[name] = [o, memfs]
    o = os.path.join(common, "gz-journal.o")
    subprocess.run(["gcc", *flags, "-c", os.path.join(SRC, "tools/gz-journal.c"), "-o", o], check=True)
    objs["gz-journal"] = [o]
    return objs


def main():
    os.makedirs(WORK, exist_ok=True)
    text = open(JOURNAL).read()
    objs = common_objects("common", CFLAGS)
    san_objs = common_objects("common-san", CFLAGS + SAN)
    linkargs = libs()
    for b in (check((9999, 0, text.split("\n")[0], text, objs, linkargs)),
              check((9999, 0, text.split("\n")[0], text, san_objs, linkargs, "san"))):
        if b[3] != "SURVIVED":
            print("the unmutated journal does not pass: %s" % b[3])
            return 1
    jobs = [(n, i, l, text, objs, linkargs) for n, (i, l) in enumerate(mutants(text))]
    results = []
    with concurrent.futures.ThreadPoolExecutor(JOBS) as ex:
        for r in ex.map(check, jobs):
            results.append(r)
            if len(results) % 50 == 0:
                print("%d of %d" % (len(results), len(jobs)), flush=True)
    survivors = [(n, i, l, text, san_objs, linkargs, "san") for n, i, l, v in results if v == "SURVIVED"]
    print("second stage, with sanitizers: %d" % len(survivors), flush=True)
    with concurrent.futures.ThreadPoolExecutor(JOBS) as ex:
        second = {r[0]: r for r in ex.map(check, survivors)}
    results = [second.get(r[0], r) for r in results]
    with open(os.path.join(WORK, "results.txt"), "w") as f:
        for n, i, l, verdict in results:
            f.write("%04d line %d: %s\n    %s\n" % (n, i + 1, verdict, l.strip()))
    counts = {}
    for r in results:
        key = r[3].split(" (")[0] if r[3].startswith("killed") else r[3]
        counts[key] = counts.get(key, 0) + 1
    print("mutants: %d; %s" % (len(results), counts))
    for n, i, l, verdict in results:
        if verdict == "SURVIVED":
            print("SURVIVED %04d line %d: %s" % (n, i + 1, l.strip()))


if __name__ == "__main__":
    sys.exit(main())
