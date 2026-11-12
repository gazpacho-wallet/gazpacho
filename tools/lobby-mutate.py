#!/usr/bin/env python3
"""Mutation testing of core/lobby (docs/ENGINEERING-CHECKLIST.md items 8 and 29).

Breaks the lobby engine in many small ways, one at a time, rebuilds it with
the sanitizers, runs the lobby tests and reports every mutant no test kills.

Operators: == and !=, < <= > >=, && and ||, return 0 and 1, a dropped logical
not, an integer constant plus one, and the removal of a one-line statement
that saves, sends, sets state or returns early.

Each test runs in its own process group and the whole group is killed on a
timeout (item 29).

usage: lobby-mutate.py REPO SECP_SRC SECP_LIB OUTDIR [WORKERS] [ONLY_FILE]
"""
import os, re, shutil, signal, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

REPO, SECP_SRC, SECP_LIB, OUT = sys.argv[1:5]
WORKERS = int(sys.argv[5]) if len(sys.argv) > 5 else 4
ONLY = sys.argv[6] if len(sys.argv) > 6 else None
FILES = ["act.c", "host.c", "member.c", "sha256.c", "terms.c", "wire.c"]
TESTS = [  # fastest first; a mutant is killed by the first that fails
    ["{q}/test_lobby_vectors"],
    ["{q}/test_lobby"],
    ["python3", "-I", "{repo}/tests/lobby/lobby_model.py", "check", "{q}/lobby_model_driver", "20000", "3"],
    ["{q}/fuzz_lobby", "20000", "5"],
    ["{q}/test_lobby_sim", "25", "0"],
    ["{q}/test_lobby_sim", "25", "1"],
    ["{q}/test_lobby_sim", "25", "2"],
]
SWAPS = [("==", "!="), ("!=", "=="), (" <= ", " < "), (" < ", " <= "), (" >= ", " > "), (" > ", " >= "),
         ("&&", "||"), ("||", "&&"), ("return 1;", "return 0;"), ("return 0;", "return 1;")]
DELETE = re.compile(r"^\s*(TRY\(|if \(.*\) TRY\(|[a-z]+->[a-z_\[\]0-9.]+ = |memcpy\(|return GZ_OK;|"
                    r"gz_lw_put\(|gz_lobby_enc_|[a-z_]+\+\+;)")


def code_lines(text):
    """Yield (index, line) for lines of code outside comments and preprocessor lines."""
    in_comment = False
    for i, line in enumerate(text.split("\n")):
        s = line.strip()
        if in_comment:
            if "*/" in s:
                in_comment = False
            continue
        if s.startswith("/*"):
            in_comment = "*/" not in s
            continue
        if not s or s.startswith("*") or s.startswith("#") or s.startswith("//"):
            continue
        yield i, line


def mutants(name, text):
    lines = text.split("\n")
    for i, line in code_lines(text):
        body = line.split("/*")[0]
        for a, b in SWAPS:
            start = 0
            while True:
                at = body.find(a, start)
                if at < 0:
                    break
                if not ((a == " < " or a == " > ") and body[at:at + 4] in (" << ", " >> ")):
                    yield (name, i, f"{a.strip()} -> {b.strip()}", line[:at] + b + line[at + len(a):])
                start = at + len(a)
        for mt in re.finditer(r"!(?!=)", body):
            yield (name, i, "drop !", line[:mt.start()] + line[mt.start() + 1:])
        if '"' not in body and "[" not in body.split("=")[0]:
            for mt in re.finditer(r"(?<![\w.])(\d+)(u|ull|ul)?(?![\w.x])", body):
                v = int(mt.group(1))
                yield (name, i, f"{v} -> {v + 1}", line[:mt.start(1)] + str(v + 1) + line[mt.end(1):])
        if DELETE.match(line) and line.rstrip().endswith(";") and line.count("(") == line.count(")"):
            yield (name, i, "delete statement", "")


def run(cmd, cwd, timeout):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        return "timeout"


INC = ["-I", f"{REPO}/core/gazpacho/include", "-I", f"{REPO}/core/lobby/include", "-I", f"{REPO}/sim",
       "-I", f"{SECP_SRC}/include"]
CC = ["gcc", "-std=gnu11", "-O1", "-w", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
MAINS = ["test_lobby_vectors", "test_lobby", "test_lobby_sim", "fuzz_lobby", "model_driver"]
OBJ = f"{OUT}/obj"


def prebuild():
    """Everything a mutant does not touch is compiled once."""
    os.makedirs(OBJ, exist_ok=True)
    srcs = {f"lobby_{f[:-2]}": f"{REPO}/core/lobby/{f}" for f in FILES}
    srcs.update({"action": f"{REPO}/core/gazpacho/action.c", "runner": f"{REPO}/core/gazpacho/runner.c",
                 "rng": f"{REPO}/sim/rng.c"})
    srcs.update({m: f"{REPO}/tests/lobby/{m}.c" for m in MAINS})
    for name, path in srcs.items():
        if run(CC + INC + ["-c", path, "-o", f"{OBJ}/{name}.o"], REPO, 300) != 0:
            sys.exit(f"prebuild failed: {path}")


def build(work, q, name):
    """Compile the mutated file, check it is still strict C11, link every test."""
    mut = f"{work}/{name}"
    if run(["gcc", "-std=c11", "-pedantic", "-ffreestanding", "-fsyntax-only", "-I", f"{REPO}/core/lobby"] + INC + [mut],
           work, 60) != 0:
        return False
    if run(CC + INC + ["-I", f"{REPO}/core/lobby", "-c", mut, "-o", f"{work}/mut.o"], work, 120) != 0:
        return False
    lib = [f"{work}/mut.o" if f == name else f"{OBJ}/lobby_{f[:-2]}.o" for f in FILES]
    lib += [f"{OBJ}/action.o", f"{OBJ}/runner.o", f"{OBJ}/rng.o"]
    for m in MAINS:
        out = "lobby_model_driver" if m == "model_driver" else m
        if run(CC + [f"{OBJ}/{m}.o"] + lib + [SECP_LIB, "-o", f"{q}/{out}"], work, 120) != 0:
            return False
    return True


def one(job):
    k, (name, i, what, new) = job
    work = tempfile.mkdtemp(prefix="mut", dir=OUT)
    try:
        lines = open(f"{REPO}/core/lobby/{name}").read().split("\n")
        lines[i] = new
        open(f"{work}/{name}", "w").write("\n".join(lines))
        q = f"{work}/q"
        os.mkdir(q)
        if not build(work, q, name):
            return (k, name, i, what, "invalid", None)
        for t, cmd in enumerate(TESTS):
            r = run([c.format(q=q, repo=REPO) for c in cmd], work, 300)
            if r != 0:
                return (k, name, i, what, "killed", t)
        return (k, name, i, what, "SURVIVED", None)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    jobs = []
    for f in FILES:
        if ONLY and f != ONLY:
            continue
        for m in mutants(f, open(f"{REPO}/core/lobby/{f}").read()):
            jobs.append(m)
    print(f"mutants: {len(jobs)}", flush=True)
    prebuild()
    log = open(f"{OUT}/results.txt", "w")
    counts = {"killed": 0, "SURVIVED": 0, "invalid": 0}
    by_test = [0] * len(TESTS)
    src = {f: open(f"{REPO}/core/lobby/{f}").read().split("\n") for f in FILES}
    with ThreadPoolExecutor(WORKERS) as ex:
        for k, name, i, what, res, t in ex.map(one, list(enumerate(jobs))):
            counts[res] += 1
            if t is not None:
                by_test[t] += 1
            log.write(f"{res} {name}:{i + 1} {what} | {src[name][i].strip()}" + (f" | test {t}" if t is not None else "") + "\n")
            log.flush()
    summary = (f"total {len(jobs)}: killed {counts['killed']}, survived {counts['SURVIVED']}, "
               f"invalid {counts['invalid']}; first kill by test: {by_test}")
    print(summary)
    log.write(summary + "\n")


main()
