#!/usr/bin/env python3
"""Helper for .github/workflows/deep-checks.yml (docs/notes/ci.md, "Deep checks").

The workflow checks out the branch under test as SRC and this file from the
workflow's own commit, so a branch made before this file existed can still be
checked. Every command writes into OUT: log.txt (the whole output),
survivors.txt (mutation shards: one surviving mutant per line) and
result.json, which the summary job merges.

  deep-checks.py plan SRC --tools LIST --shards K
      The mutation matrix for the tools present in SRC, as GitHub output lines
      (mutation=<json>, mutation_count=<n>). LIST: "all" or names separated by
      commas. K: shards per tool, 0 for each tool's default.
  deep-checks.py mutate SRC TOOL SHARD OF OUT [--budget MIN] [--jobs N]
      Prepare and run one shard of one mutation tool.
  deep-checks.py tests BUILD SHARD OF [--compiled]
      The regular expression that selects this shard's CTest tests (empty if
      none). --compiled: only tests whose program is built in BUILD (the ones
      tools/valgrind-tests.py runs).
  deep-checks.py run NAME OUT [--budget MIN] -- COMMAND...
      Run any command with a log and a result.json.
  deep-checks.py summary DIR OUT
      Merge every result.json and survivors.txt under DIR into OUT/summary.md
      and OUT/survivors.txt.

Standard library only. Builds nothing on its own except what a mutation tool
needs before it starts.
"""
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

# One entry per mutation tool. list: the mutant list (None: the tool generates
# its mutants); sep: the field separator of the list; shards: the default
# number of shards; prep: what the tool needs before it starts; cmd: its
# arguments ({src}, {work}, {build}, {jobs} filled in; the shard's mutant names
# follow); style: how a survivor is printed ("first": SURVIVED NAME,
# "second": NAME SURVIVED).
TOOLS = {
    "tree": dict(script="tools/mutate-tree.py", list="tests/tree/mutants.txt", sep="\t", shards=6, prep=None,
                 cmd=["{src}", "{work}", "-j", "{jobs}"], style="first"),
    "node": dict(script="tools/mutate-node.py", list="tests/node/mutants.txt", sep="\t", shards=4, prep=None,
                 cmd=["{src}", "{work}", "-j", "{jobs}"], style="first"),
    "api": dict(script="tools/mutate-api.py", list="tests/api/mutants.txt", sep="\t", shards=3, prep=None,
                cmd=["{src}", "-j", "{jobs}"], style="second"),
    "chain-watch": dict(script="tools/mutate-chain-watch.py", list="ports/chain/tests/watch_mutants.txt", sep=" ## ",
                        shards=2, prep=None, cmd=["-j", "{jobs}"], style="first"),
    "net": dict(script="tools/mutate-net.py", list="tests/net/mutants.txt", sep="\t", shards=8, prep="secp",
                cmd=["--first", "{src}", "{build}"], style="first"),
    "storage": dict(script="tools/mutate-storage.py", list="ports/storage/crypto/tests/mutants.txt", sep="\t",
                    shards=4, prep="full", cmd=["{src}", "{build}"], style="first"),
    "keys": dict(script="tools/mutate-keys.py", list="tests/program/keys_mutants.txt", sep="\t", shards=3, prep=None,
                 cmd=["{src}", "{work}"], style="second"),
    "s5s6": dict(script="tools/mutate-s5s6.py", list="tools/mutants-s5s6.txt", sep="\t", shards=3, prep="configure",
                 cmd=["{src}", "{build}", "{work}"], style="second"),
    "lobby": dict(script="tools/lobby-mutate.py", list=None, shards=6, prep="secp", style="lobby"),
    "signing": dict(script="tools/signing-mutants.py", list=None, shards=16, prep="signing", style="signing"),
}
SIGNING_TARGETS = ["test_signing", "test_signing_wb", "test_round_msg", "test_bip341", "test_bip327"]
CONFIGURE = ["-DCMAKE_BUILD_TYPE=Release", "-DGZW_BREAK_CHECKS=OFF", "-DGZ_MUTATION_BUILD=ON"]


def out_line(key, value):
    path = os.environ.get("GITHUB_OUTPUT")
    line = "%s=%s\n" % (key, value)
    if path:
        with open(path, "a") as f:
            f.write(line)
    sys.stdout.write(line)


# --- mutant lists ------------------------------------------------------------

def list_names(src, tool):
    """Every mutant of a tool, in the tool's own order (duplicates dropped)."""
    t = TOOLS[tool]
    if t["list"]:
        names = []
        with open(os.path.join(src, t["list"]), encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip() or line.startswith("#"):
                    continue
                names.append(line.split(t["sep"])[0].strip())
    elif tool == "signing":
        names = [v[0] for v in load_module(os.path.join(src, t["script"]), "signing_mutants").mutant_variants(src)]
    elif tool == "lobby":
        names = ["%s:%d %s" % (j[0], j[1] + 1, j[2]) for j in lobby_jobs(src)]
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def lobby_jobs(src):
    """lobby-mutate.py's own job list, in its order. The tool runs main() when
    loaded, so its text is run without that last call."""
    path = os.path.join(src, TOOLS["lobby"]["script"])
    code = open(path, encoding="utf-8").read()
    body = re.sub(r"\nmain\(\)\s*$", "\n", code)
    if body == code:
        sys.exit("lobby-mutate.py no longer ends with main(): update tools/deep-checks.py")
    saved = sys.argv
    sys.argv = [path, src, "-", "-", "-"]
    try:
        g = {"__name__": "lobby_mutate_plan", "__file__": path}
        exec(compile(body, path, "exec"), g)
        jobs = list(g["named_mutants"](None))
        for f in g["FILES"]:
            with open(os.path.join(src, "core", "lobby", f), encoding="utf-8") as fh:
                jobs.extend(g["mutants"](f, fh.read()))
    finally:
        sys.argv = saved
    return jobs


def shard_of(items, shard, of):
    return [x for i, x in enumerate(items) if i % of == shard]


# --- plan ----------------------------------------------------------------------

def cmd_plan(args):
    src = args[0]
    want, shards = "all", 0
    rest = args[1:]
    while rest:
        a = rest.pop(0)
        if a == "--tools":
            want = rest.pop(0).strip() or "all"
        elif a == "--shards":
            shards = int(rest.pop(0) or "0")
    names = list(TOOLS) if want == "all" else [n.strip() for n in want.split(",") if n.strip()]
    unknown = [n for n in names if n not in TOOLS]
    if unknown:
        sys.exit("unknown mutation tools: %s (known: %s)" % (", ".join(unknown), ", ".join(TOOLS)))
    matrix = []
    for tool in names:
        t = TOOLS[tool]
        if not os.path.exists(os.path.join(src, t["script"])):
            print("::notice::%s is not on this ref; mutation tool %s skipped" % (t["script"], tool))
            continue
        try:
            count = len(list_names(src, tool))
        except (OSError, SystemExit, Exception) as e:   # a broken list is reported by the shard, not here
            print("::warning::%s: cannot count its mutants (%s); one shard" % (tool, e))
            count = 1
        n = max(1, min(shards or t["shards"], count))
        for s in range(n):
            matrix.append({"tool": tool, "shard": s, "of": n})
        if tool == "signing":
            matrix.append({"tool": "signing-rules", "shard": 0, "of": 1})
        print("%s: %d mutants, %d shards" % (tool, count, n))
    out_line("mutation", json.dumps({"include": matrix}, separators=(",", ":")))
    out_line("mutation_count", str(len(matrix)))


# --- running with a log and a deadline -----------------------------------------

def run_logged(cmd, log, deadline, cwd=None, env=None):
    """Run cmd, copying its output to the console and to log. Returns its exit
    code, or None if it was stopped at the deadline."""
    log.write("$ %s\n" % " ".join(cmd))
    log.flush()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True)

    def pump():
        for line in iter(p.stdout.readline, b""):
            sys.stdout.buffer.write(line)
            sys.stdout.flush()
            log.write(line.decode(errors="replace"))
            log.flush()

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    try:
        p.wait(timeout=max(1, deadline - time.time()))
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.wait()
        reader.join(10)
        log.write("\nSTOPPED: the shard's time budget ran out\n")
        log.flush()
        return None
    reader.join()
    return p.returncode


def write_result(out, **fields):
    with open(os.path.join(out, "result.json"), "w") as f:
        json.dump(fields, f, indent=1, sort_keys=True)


def parse_opts(args, opts):
    rest, pos = list(args), []
    while rest:
        a = rest.pop(0)
        if a == "--":
            pos.extend(rest)
            break
        if a.startswith("--") and a[2:] in opts:
            kind = opts[a[2:]]
            opts[a[2:]] = True if kind is False else type(kind)(rest.pop(0))
        else:
            pos.append(a)
    return pos, opts


def cmd_run(args):
    pos, o = parse_opts(args, {"budget": 330})
    name, out, cmd = pos[0], pos[1], pos[2:]
    os.makedirs(out, exist_ok=True)
    start = time.time()
    with open(os.path.join(out, "log.txt"), "a") as log:
        rc = run_logged(cmd, log, start + o["budget"] * 60)
    status = "timeout" if rc is None else ("ok" if rc == 0 else "failed")
    write_result(out, name=name, kind="run", status=status, exit=rc, seconds=round(time.time() - start))
    return 0 if rc == 0 else 1


# --- mutation shards --------------------------------------------------------------

def prepare(src, work, kind, log, deadline, jobs):
    """Returns the build directory the tool needs (or None)."""
    if kind is None:
        return None
    if kind == "signing":
        return None   # prepared in cmd_mutate
    build = os.path.join(work, "build")
    if run_logged(["cmake", "-S", src, "-B", build] + CONFIGURE, log, deadline) != 0:
        sys.exit("configure failed")
    if kind == "secp":
        target = ["--target", "secp256k1"]
    elif kind == "full":
        target = []
    else:
        return build
    if run_logged(["cmake", "--build", build, "-j", str(jobs)] + target, log, deadline) != 0:
        sys.exit("the build the tool needs failed")
    return build


def prepare_signing(src, work, log, deadline, jobs):
    builds, secp = [], None
    for i in range(1, jobs + 1):
        w = os.path.join(work, "w%d" % i)
        wsrc, wbuild = os.path.join(w, "src"), os.path.join(w, "build")
        shutil.copytree(src, wsrc, ignore=shutil.ignore_patterns(".git", "build*"), symlinks=True)
        cfg = ["cmake", "-S", wsrc, "-B", wbuild] + CONFIGURE
        if secp:
            cfg.append("-DFETCHCONTENT_SOURCE_DIR_SECP256K1-ZKP=" + secp)
        if run_logged(cfg, log, deadline) != 0:
            sys.exit("configure failed")
        if not secp:
            secp = os.path.join(wbuild, "_deps", "secp256k1-zkp-src")
        if run_logged(["cmake", "--build", wbuild, "-j", str(jobs), "--target"] + SIGNING_TARGETS, log, deadline) != 0:
            sys.exit("the signing tests do not build")
        builds.append(wbuild)
    return builds


def survivors_of(style, text):
    out = []
    for line in text.splitlines():
        if style == "first":
            m = re.match(r"^SURVIVED\s+(\S+)", line)
        elif style == "second":
            m = re.match(r"^(\S+)\s+SURVIVED\b", line)
        elif style == "signing":
            m = re.match(r"^(?:SURVIVOR|MISSING) (.+)$", line)
        else:   # lobby: its results file
            m = re.match(r"^SURVIVED (.+)$", line)
        if m and m.group(1) not in out:
            out.append(m.group(1).strip())
    return out


def cmd_mutate(args):
    pos, o = parse_opts(args, {"budget": 330, "jobs": os.cpu_count() or 2})
    tool, shard, of, out = pos[1], int(pos[2]), int(pos[3]), os.path.abspath(pos[4])
    start = time.time()
    try:
        return mutate(os.path.abspath(pos[0]), tool, shard, of, out, o)
    except SystemExit as e:   # the tool's preparation failed: still leave a result for the summary
        if e.code in (None, 0):
            raise
        print("FAILED before the run: %s" % e.code)
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "log.txt"), "a") as log:
            log.write("\nFAILED before the run: %s\n" % e.code)
        open(os.path.join(out, "survivors.txt"), "a").close()
        write_result(out, name="%s %d/%d" % (tool, shard + 1, of), kind="mutation", tool=tool, shard=shard, of=of,
                     status="failed", exit=None, mutants=None, survivors=0, seconds=round(time.time() - start),
                     note=str(e.code))
        return 1


def mutate(src, tool, shard, of, out, o):
    jobs = o["jobs"]
    os.makedirs(out, exist_ok=True)
    start = time.time()
    deadline = start + o["budget"] * 60
    work = os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "mut-%s-%d" % (tool, shard))
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    py = [sys.executable, "-I"]
    base = "signing" if tool == "signing-rules" else tool
    t = TOOLS[base]
    env = dict(os.environ)
    survivors_file = None
    with open(os.path.join(out, "log.txt"), "w") as log:
        if tool == "signing-rules":
            names = []
        else:
            names = shard_of(list_names(src, base), shard, of)
            if not names:
                write_result(out, name="%s %d/%d" % (tool, shard + 1, of), kind="mutation", tool=tool, shard=shard,
                             of=of, status="ok", exit=0, mutants=0, survivors=0, seconds=0)
                open(os.path.join(out, "survivors.txt"), "w").close()
                print("no mutants in this shard")
                return 0
        log.write("%s shard %d of %d: %d mutants\n" % (tool, shard + 1, of, len(names)))
        script = os.path.join(src, t["script"])
        if base == "signing":
            builds = prepare_signing(src, work, log, deadline, jobs)
            if tool == "signing-rules":
                cmd = py + [script, "rules", src] + builds
            else:
                nf = os.path.join(work, "names.txt")
                with open(nf, "w") as f:
                    f.write("".join(n + "\n" for n in names))
                cmd = py + [script, "mutants", src] + builds + ["--names", nf]
        elif base == "lobby":
            build = prepare(src, work, "secp", log, deadline, jobs)
            keep = set(names)
            again = os.path.join(work, "shard.txt")
            with open(again, "w") as f:
                for j in lobby_jobs(src):
                    key = "%s:%d %s" % (j[0], j[1] + 1, j[2])
                    if key in keep:
                        f.write("SURVIVED %s | -\n" % key)
            env["MUT_AGAIN"] = again
            outdir = os.path.join(work, "out")
            secp_src = os.path.join(build, "_deps", "secp256k1-zkp-src")
            secp_lib = os.path.join(build, "_deps", "secp256k1-zkp-build", "src", "libsecp256k1.a")
            cmd = py + [script, src, secp_src, secp_lib, outdir, str(jobs)]
            survivors_file = os.path.join(outdir, "results.txt")
        else:
            build = prepare(src, work, t["prep"], log, deadline, jobs)
            fill = {"{src}": src, "{work}": os.path.join(work, "w"), "{build}": build or "", "{jobs}": str(jobs)}
            cmd = py + [script] + [fill.get(a, a) for a in t["cmd"]] + names
        rc = run_logged(cmd, log, deadline, cwd=work, env=env)
    text = open(os.path.join(out, "log.txt"), errors="replace").read()
    if survivors_file:
        if os.path.exists(survivors_file):
            shutil.copy(survivors_file, os.path.join(out, "results.txt"))
            text = open(survivors_file, errors="replace").read()
        else:
            text = ""
    surv = survivors_of(t["style"], text)
    with open(os.path.join(out, "survivors.txt"), "w") as f:
        f.write("".join("%s\t%s\n" % (tool, s) for s in surv))
    status = "timeout" if rc is None else ("ok" if rc == 0 else "failed")
    write_result(out, name="%s %d/%d" % (tool, shard + 1, of), kind="mutation", tool=tool, shard=shard, of=of,
                 status=status, exit=rc, mutants=len(names) if tool != "signing-rules" else None,
                 survivors=len(surv), seconds=round(time.time() - start))
    return 0 if rc == 0 else 1


# --- CTest shards -------------------------------------------------------------------

def cmd_tests(args):
    pos, o = parse_opts(args, {"compiled": False})
    build, shard, of = os.path.abspath(pos[0]), int(pos[1]), int(pos[2])
    info = json.loads(subprocess.run(["ctest", "--test-dir", build, "--show-only=json-v1"], check=True,
                                     capture_output=True, text=True).stdout)
    names = []
    for t in info.get("tests", []):
        cmd = t.get("command") or []
        if o["compiled"] and (not cmd or not os.path.abspath(cmd[0]).startswith(build + os.sep)):
            continue
        names.append(t["name"])
    mine = shard_of(sorted(names), shard, of)
    print("^(%s)$" % "|".join(re.escape(n) for n in mine) if mine else "")


# --- summary ----------------------------------------------------------------------------

def cmd_summary(args):
    src, out = args[0], args[1]
    os.makedirs(out, exist_ok=True)
    results, survivors = [], []
    for root, _, files in os.walk(src):
        if "result.json" in files:
            with open(os.path.join(root, "result.json")) as f:
                r = json.load(f)
            r["artifact"] = os.path.relpath(root, src)
            results.append(r)
        if "survivors.txt" in files:
            with open(os.path.join(root, "survivors.txt"), errors="replace") as f:
                survivors.extend(l.rstrip("\n") for l in f if l.strip())
    results.sort(key=lambda r: (r.get("kind", ""), r.get("tool", ""), r.get("name", "")))
    bad = [r for r in results if r.get("status") != "ok"]
    lines = ["# Deep checks", ""]
    lines.append("%d shards: %d ok, %d failed or stopped; %d surviving mutants." % (
        len(results), len(results) - len(bad), len(bad), len(survivors)))
    lines += ["", "| Shard | Status | Exit | Mutants | Survivors | Minutes |", "|---|---|---|---|---|---|"]
    for r in results:
        lines.append("| %s | %s | %s | %s | %s | %.0f |" % (
            r.get("name"), r.get("status"), r.get("exit"), "" if r.get("mutants") is None else r.get("mutants"),
            "" if r.get("kind") != "mutation" else r.get("survivors"), (r.get("seconds") or 0) / 60.0))
    if survivors:
        lines += ["", "## Surviving mutants", "", "```"] + sorted(survivors) + ["```"]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write(text)
    with open(os.path.join(out, "survivors.txt"), "w") as f:
        f.write("".join(s + "\n" for s in sorted(survivors)))
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a") as f:
            f.write(text)
    print(text)
    return 0


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    fn = {"plan": cmd_plan, "mutate": cmd_mutate, "tests": cmd_tests, "run": cmd_run, "summary": cmd_summary}.get(cmd)
    if not fn:
        sys.exit(__doc__)
    return fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
