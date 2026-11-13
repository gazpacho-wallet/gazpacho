#!/usr/bin/env python3
"""Mutation testing of core/lobby (docs/ENGINEERING-CHECKLIST.md items 8 and 29).

Breaks the lobby engine in many small ways, one at a time, rebuilds it with
the sanitizers, runs the lobby tests and reports every mutant no test kills.

Operators: == and !=, < <= > >=, && and ||, return 0 and 1, a dropped logical
not, an integer constant plus one, and the removal of a one-line statement
that saves, sends, sets state or returns early.

Each test runs in its own process group and the whole group is killed on a
timeout (item 29).

usage: lobby-mutate.py REPO SECP_SRC SECP_LIB OUTDIR [WORKERS] [FILE,FILE...]
"""
import os, re, shutil, signal, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

REPO, SECP_SRC, SECP_LIB, OUT = sys.argv[1:5]
WORKERS = int(sys.argv[5]) if len(sys.argv) > 5 else 4
ONLY = sys.argv[6].split(",") if len(sys.argv) > 6 else None
FILES = ["act.c", "host.c", "member.c", "sha256.c", "terms.c", "wire.c"]
TESTS = [  # fastest first; a mutant is killed by the first that fails
    ["{q}/test_lobby_vectors"],
    ["{q}/test_lobby"],
    ["python3", "-I", "{repo}/tests/lobby/lobby_model.py", "check", "{q}/lobby_model_driver", "20000", "3"],
    ["{q}/fuzz_lobby", "20000", "5"],
    ["{q}/test_lobby_sim_fast", "20", "0"],
    ["{q}/test_lobby_sim_fast", "20", "1"],
    ["{q}/test_lobby_sim_fast", "20", "2"],
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


# Real stack frames, not AddressSanitizer's separate ones, so that a byte an
# engine leaves unwritten keeps the 0xa5 the tests put there (test_lobby.c,
# poison_stack) and fails the byte-exact checks.
ENV = dict(os.environ, ASAN_OPTIONS="detect_stack_use_after_return=0")


def run(cmd, cwd, timeout):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                         env=ENV)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        return "timeout"


INC = ["-I", f"{REPO}/core/gazpacho/include", "-I", f"{REPO}/core/lobby/include", "-I", f"{REPO}/sim",
       "-I", f"{SECP_SRC}/include"]
CC = ["gcc", "-std=gnu11", "-O1", "-w", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
MAINS = ["test_lobby_vectors", "test_lobby", "test_lobby_sim", "fuzz_lobby", "fuzz_lobby_main", "model_driver"]
OBJ = f"{OUT}/obj"
FAST = ["gcc", "-std=gnu11", "-O2", "-w"]           # the simulator runs long: built without the checkers


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
        if run(FAST + INC + ["-c", path, "-o", f"{OBJ}/{name}.fast.o"], REPO, 300) != 0:
            sys.exit(f"prebuild failed: {path}")


def build(work, name):
    """Compile the mutated file; it must still be strict C11."""
    mut = f"{work}/{name}"
    if run(["gcc", "-std=c11", "-pedantic", "-ffreestanding", "-fsyntax-only", "-I", f"{REPO}/core/lobby"] + INC + [mut],
           work, 60) != 0:
        return False
    for cc, obj in ((CC, "mut.o"), (FAST, "mut.fast.o")):
        if run(cc + INC + ["-I", f"{REPO}/core/lobby", "-c", mut, "-o", f"{work}/{obj}"], work, 120) != 0:
            return False
    return True


def link(work, name, binary):
    """Link one test program with the mutated object, when a test first needs it."""
    out = f"{work}/q/{binary}"
    if os.path.exists(out):
        return True
    fast = binary.endswith("_fast")
    sfx = ".fast.o" if fast else ".o"
    objs = [f"{work}/mut{sfx}" if f == name else f"{OBJ}/lobby_{f[:-2]}{sfx}" for f in FILES]
    objs += [f"{OBJ}/action{sfx}", f"{OBJ}/runner{sfx}", f"{OBJ}/rng{sfx}"]
    main_obj = {"lobby_model_driver": "model_driver", "test_lobby_sim_fast": "test_lobby_sim"}.get(binary, binary)
    mains = [main_obj] + (["fuzz_lobby_main"] if binary == "fuzz_lobby" else [])
    return run((FAST if fast else CC) + [f"{OBJ}/{m}{sfx}" for m in mains] + objs + [SECP_LIB, "-o", out], work, 120) == 0


def one(job):
    k, (name, i, what, new) = job
    work = tempfile.mkdtemp(prefix="mut", dir=OUT)
    try:
        lines = open(f"{REPO}/core/lobby/{name}").read().split("\n")
        lines[i] = new
        open(f"{work}/{name}", "w").write("\n".join(lines))
        os.mkdir(f"{work}/q")
        if not build(work, name):
            return (k, name, i, what, "invalid", None)
        for t, cmd in enumerate(TESTS):
            binary = next(c for c in cmd if c.startswith("{q}/"))[4:]
            if not link(work, name, binary):
                return (k, name, i, what, "invalid", None)
            r = run([c.format(q=f"{work}/q", repo=REPO) for c in cmd], work, 90)
            if r != 0:
                return (k, name, i, what, "killed", t)
        return (k, name, i, what, "SURVIVED", None)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    jobs = []
    for f in FILES:
        if ONLY and f not in ONLY:
            continue
        for m in mutants(f, open(f"{REPO}/core/lobby/{f}").read()):
            jobs.append(m)
    again = os.environ.get("MUT_AGAIN")             # a results file: run only its survivors again
    if again:
        keep = set()
        for line in open(again):
            if line.startswith("SURVIVED "):
                where, what = line.split(" ", 1)[1].split(" | ")[0].split(" ", 1)
                keep.add((where, what))
        jobs = [j for j in jobs if (f"{j[0]}:{j[1] + 1}", j[2]) in keep]
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
