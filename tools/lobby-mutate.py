#!/usr/bin/env python3
"""Mutation testing of core/lobby (docs/ENGINEERING-CHECKLIST.md items 8 and 29).

Breaks the lobby engine in many small ways, one at a time, rebuilds it with
the sanitizers, runs the lobby tests and reports every mutant no test kills.

Operators: == and !=, < <= > >=, && and ||, return 0 and 1, a dropped logical
not, an integer constant plus one, and the removal of a one-line statement
that saves, sends, sets state, writes a record's field or returns early.

Beside those, a list of named mutants (NAMED below) for the rules of contract
v2 that the operators do not reach in one step: the member's link check, the
scope and largest-size checks of restore, the fields a record may have, the
free locked/ready pair, the four conditions of gz_lobby_member_accepted, the
budget timer that is not set in Signing, the signing gate, the refusal's
DISCONNECT and CONNECT, a port that will not sign. Each is an exact piece of
core/lobby's text and its replacement: the tool stops at once if one no longer
applies exactly once, so the list cannot rot silently when the code moves.

A line mutant's name gives the column it changed (@N), and the results
give the mutated line after `now:`. Each test runs in its own process group and the whole group is killed on a
timeout (item 29).

usage: lobby-mutate.py REPO SECP_SRC SECP_LIB OUTDIR [WORKERS] [FILE,FILE...]
       FILE may be `named`: only the named mutants (alone, or with files).
"""
import os, re, shutil, signal, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

REPO, SECP_SRC, SECP_LIB, OUT = sys.argv[1:5]
WORKERS = int(sys.argv[5]) if len(sys.argv) > 5 else 4
ONLY = sys.argv[6].split(",") if len(sys.argv) > 6 else None
FILES = ["act.c", "fit.c", "host.c", "member.c", "wire.c"]
TREE = ["sha256", "terms", "shape", "model", "checks", "exit"]   # core/tree, never mutated here
TESTS = [  # fastest first; a mutant is killed by the first that fails
    ["{q}/test_lobby_vectors"],
    ["{q}/test_lobby_v2"],
    ["{q}/test_lobby"],
    ["{q}/test_lobby_hostile", "20000", "3"],
    ["python3", "-I", "{repo}/tests/lobby/lobby_model.py", "check", "{q}/lobby_model_driver", "20000", "3"],
    ["{q}/fuzz_lobby", "20000", "5"],
    ["{q}/fuzz_lobby_seq", "1500", "5"],
    ["{q}/test_lobby_sim_fast", "20", "0"],
    ["{q}/test_lobby_sim_fast", "20", "1"],
    ["{q}/test_lobby_sim_fast", "20", "2"],
]
SWAPS = [("==", "!="), ("!=", "=="), (" <= ", " < "), (" < ", " <= "), (" >= ", " > "), (" > ", " >= "),
         ("&&", "||"), ("||", "&&"), ("return 1;", "return 0;"), ("return 0;", "return 1;")]
DELETE = re.compile(r"^\s*(TRY\(|if \(.*\) TRY\(|[a-z]+->[a-z_\[\]0-9.]+ = |memcpy\(|return GZ_OK;|"
                    r"gz_lw_put\(|gz_lr_put\(|gz_lr_int\(|gz_lobby_enc_|[a-z_]+\+\+;)")


# Named mutants: (file, what it breaks, the exact text, its replacement).
NAMED = [
    # the member takes inputs only on its own link (our key, the pinned host key)
    ("member.c", "link check: any local key",
     "if (memcmp(in->link.local.key, m->ckey, 33) != 0 || memcmp(in->link.remote.key, m->host_key, 33) != 0)",
     "if (memcmp(in->link.remote.key, m->host_key, 33) != 0)"),
    ("member.c", "link check: any remote key",
     "if (memcmp(in->link.local.key, m->ckey, 33) != 0 || memcmp(in->link.remote.key, m->host_key, 33) != 0)",
     "if (memcmp(in->link.local.key, m->ckey, 33) != 0)"),
    # restore: the record's scope
    ("member.c", "restore: any scope",
     "!gz_lf_read(rec->bytes.data, rec->bytes.len, m->scope, &f) ||",
     "!gz_lf_read(rec->bytes.data, rec->bytes.len, NULL, &f) ||"),
    ("host.c", "restore: any scope",
     "rec->type == GZ_REC_LOBBY_OPENED || h->state == GZ_LOBBY_UNKNOWN ? NULL : h->scope, &f) ||",
     "rec->type == GZ_REC_LOBBY_OPENED || h->state == GZ_LOBBY_UNKNOWN ? NULL : NULL, &f) ||"),
    ("act.c", "a record's scope: any 32 bytes compared",
     "return !scope || memcmp(f->v[1], scope, 32) == 0;",
     "return !scope || memcmp(f->v[1], scope, 31) == 0;"),
    # restore: the largest size of each record type
    ("host.c", "restore: no largest size",
     "if (len > gz_lobby_rec_max(rec->type) ||\n        !gz_lf_read(p, len,",
     "if (!gz_lf_read(p, len,"),
    ("member.c", "restore: no largest size",
     "if (rec->bytes.len > gz_lobby_rec_max(rec->type) || !gz_lf_read(",
     "if (!gz_lf_read("),
    ("act.c", "rec_scope: no largest size",
     "!gz_lobby_rec_max(rec->type) || rec->bytes.len > gz_lobby_rec_max(rec->type) ||",
     "!gz_lobby_rec_max(rec->type) ||"),
    ("act.c", "the table: a row one byte larger",
     "{GZ_REC_LOBBY_STATE, GZ_LOBBY_REC_MAX_STATE, \"lobby_state\"},",
     "{GZ_REC_LOBBY_STATE, GZ_LOBBY_REC_MAX_STATE + 1, \"lobby_state\"},"),
    # restore: an even field the record type has not
    ("act.c", "restore: unknown even fields taken",
     "if (f->v[t / 2] && !(known & FLD(t))) return 0;",
     "if (0) return 0;"),
    ("host.c", "restore: the fields are not checked",
     " ||\n        !gz_lf_known(rec->type, &f))\n        return GZ_ERR_CORRUPT;\n    if (rec->type != GZ_REC_LOBBY_OPENED",
     ")\n        return GZ_ERR_CORRUPT;\n    if (rec->type != GZ_REC_LOBBY_OPENED"),
    ("member.c", "restore: the fields are not checked",
     " ||\n        !gz_lf_known(rec->type, &f))\n        return GZ_ERR_CORRUPT;\n    switch (rec->type) {\n    case GZ_REC_TERMS_RECEIVED:",
     ")\n        return GZ_ERR_CORRUPT;\n    switch (rec->type) {\n    case GZ_REC_TERMS_RECEIVED:"),
    # the locked unready and the ready after it: free once per check window
    ("host.c", "free pair: every window",
     "int free_pair = s->locked && s->free_window != h->window_no + 1;",
     "int free_pair = s->locked;"),
    ("host.c", "free pair: never for the ready",
     "int free_pair = s->locked && s->free_window != h->window_no + 1;",
     "int free_pair = 0;"),
    ("host.c", "free pair: the window is not marked used",
     "if (free_pair) s->free_window = h->window_no + 1;",
     ""),
    ("host.c", "free pair: every locked unready free",
     "seat_change(h, s, want, locked && s->free_window != h->window_no + 1 ? 2 : 1, &st, out);",
     "seat_change(h, s, want, locked ? 2 : 1, &st, out);"),
    ("host.c", "free pair: the locked unready counted",
     "seat_change(h, s, want, locked && s->free_window != h->window_no + 1 ? 2 : 1, &st, out);",
     "seat_change(h, s, want, 1, &st, out);"),
    ("host.c", "free pair: the seat is not marked locked",
     "if (s && locked) s->locked = 1;",
     ""),
    ("host.c", "free pair: an uncounted change is counted",
     "if (force != 2) {",
     "if (1) {"),
    ("host.c", "free pair: reason 3 is not the lock",
     "int locked = m->kind == GZ_KIND_UNREADY && m->has_reason && m->reason == 3;",
     "int locked = m->kind == GZ_KIND_UNREADY && m->has_reason && m->reason == 2;"),
    # gz_lobby_member_accepted
    ("member.c", "accepted: a higher attempt",
     "if (!m || !check_id || attempt > 1) return 0;",
     "if (!m || !check_id) return 0;"),
    ("member.c", "accepted: any check, not the one answered",
     "memcmp(m->answered_check, check_id, 32) != 0 || m->ready_version != m->frozen_version)",
     "m->ready_version != m->frozen_version)"),
    ("member.c", "accepted: without an answer",
     "!m->frozen || !m->has_answered ||\n        memcmp(m->answered_check",
     "!m->frozen ||\n        memcmp(m->answered_check"),
    ("member.c", "accepted: though not ready (withdrawn)",
     "if (!m->ready || m->user_unready || m->ended || !m->frozen",
     "if (m->user_unready || m->ended || !m->frozen"),
    ("member.c", "accepted: though the lobby ended",
     "if (!m->ready || m->user_unready || m->ended || !m->frozen",
     "if (!m->ready || m->user_unready || !m->frozen"),
    ("member.c", "accepted: a spent attempt (Funding, Active)",
     "if (m->round_state >= GZ_LOBBY_FUNDING) return 0;",
     ""),
    ("member.c", "accepted: a start with role 2",
     "if (role == 2) return 0;                          /* not chosen in that attempt */",
     ""),
    ("member.c", "accepted: the hand-off without the start",
     "ho->start_bytes = m->start_msg; ho->start_len = m->start_len;",
     ""),
    ("member.c", "a Retry does not spend an answer without a start",
     "return start_role_of(m, check, NULL) != 0 || (m->has_answered && memcmp(m->answered_check, check, 32) == 0);",
     "return start_role_of(m, check, NULL) != 0;"),
    # the budget: the lobby's timer only with no round in flight
    ("host.c", "budget timer: set at the first start",
     "    h->started = 1;\n    /* No budget timer here:",
     "    h->started = 1;\n    if (first) TRY(budget_timer(h, out));\n    /* No budget timer here:"),
    ("host.c", "budget timer: set at a resume in Signing",
     "if (h->budget_ms && h->state == GZ_LOBBY_OPEN) TRY(budget_timer(h, out));",
     "if (h->budget_ms) TRY(budget_timer(h, out));"),
    ("host.c", "budget timer: cancels a round in Signing",
     "if (h->state == GZ_LOBBY_SIGNING) return GZ_OK;\n            if (now_ms(h) < h->budget_ms",
     "if (now_ms(h) < h->budget_ms"),
    ("host.c", "budget timer: not set after a retry",
     "    TRY(budget_timer(h, out));\n    if (now_ms(h) / 1000 < h->terms.deadline) TRY(deadline_timer(h, out));",
     "    if (now_ms(h) / 1000 < h->terms.deadline) TRY(deadline_timer(h, out));"),
    ("host.c", "hand-off: no end of the budget",
     "ho.budget_end_ms = h->budget_ms + h->terms.signing_budget_ms;",
     "ho.budget_end_ms = 0;"),
    # the signing gate
    ("member.c", "gate: readies behind a closed gate",
     "if (locked(m)) {                          /* \"unlock to take part\" */",
     "if (0) {"),
    ("member.c", "gate: answers a check behind a closed gate",
     "    if (locked(m)) {\n        if (m->ready && !check_in_flight(m)) return lock_out(m, out);",
     "    if (0) {\n        if (m->ready && !check_in_flight(m)) return lock_out(m, out);"),
    ("member.c", "gate: a check in flight is withdrawn",
     "if (m->ended || !m->joined || !m->ready || check_in_flight(m)) return GZ_OK;",
     "if (m->ended || !m->joined || !m->ready) return GZ_OK;"),
    ("member.c", "gate: no locked unready at a resume",
     "if (locked(m)) TRY(lock_out(m, out));\n    if (m->ended || !m->start_len",
     "if (m->ended || !m->start_len"),
    ("member.c", "gate: no locked unready after a retry",
     "        if (locked(m)) TRY(lock_out(m, out));\n    }\n    return GZ_OK;                                     /* Failed",
     "    }\n    return GZ_OK;                                     /* Failed"),
    ("member.c", "gate: closing it does nothing",
     "m->locked_told = 0;\n    return locked(m) ? lock_out(m, out) : GZ_OK;",
     "m->locked_told = 0;\n    return GZ_OK;"),
    ("member.c", "gate: the locked unready has another reason",
     "TRY(unready(m, 3, out));",
     "TRY(unready(m, 2, out));"),
    ("member.c", "gate: a locked member says nothing to a check",
     "if (!m->ready) TRY(unready(m, 3 /* locked */, out));",
     ""),
    # refusals, connections, the engine rule
    ("member.c", "refusal: no CONNECT after it",
     "return m->ended ? GZ_OK : gz_lobby_member_connect(m, out);",
     "return GZ_OK;"),
    ("member.c", "resume: no CONNECT",
     "TRY(gz_lobby_member_connect(m, out));             /* at every start (action.h, CONNECTIONS) */",
     ""),
    ("member.c", "no key: an error",
     "if (!len) return gz_la_no_key(out, GZ_LOBBY_KEY_CONTRIBUTION);",
     "if (!len) return GZ_ERR_ARGUMENT;"),
    ("host.c", "no key: an error",
     "if (!h->check_len) return gz_la_no_key(out, GZ_LOBBY_KEY_HOST);",
     "if (!h->check_len) return GZ_ERR_ARGUMENT;"),
    ("host.c", "no key: new values not refused",
     "if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, cd, sig) != 1) return gz_la_no_key(out, GZ_LOBBY_KEY_HOST);",
     "if (h->crypto.sign(h->crypto.ctx, GZ_LOBBY_KEY_HOST, cd, sig) != 1) return GZ_ERR_ARGUMENT;"),
    ("host.c", "a 65th connection: an error",
     "if (i == GZ_LOBBY_MAX_CONNS) return gz_la_refuse(out, &in->link);",
     "if (i == GZ_LOBBY_MAX_CONNS) return GZ_ERR_ARGUMENT;"),
    ("host.c", "a reconnect does not reuse its entry",
     "    gz_lobby_conn_t *c = conn_of(h, &in->link);\n    int i;\n    if (!c) {",
     "    gz_lobby_conn_t *c = NULL;\n    int i;\n    if (!c) {"),
    ("host.c", "a scope-zero hello answered",
     "return any ? gz_lobby_host_unknown(&c->link, m->scope, out) : GZ_OK;",
     "return gz_lobby_host_unknown(&c->link, m->scope, out);"),
    ("host.c", "the listing: a lobby that ended",
     "if (!h->cfg.listed || h->state < GZ_LOBBY_OPEN || h->state > GZ_LOBBY_SIGNING) return GZ_OK;",
     "if (!h->cfg.listed || h->state < GZ_LOBBY_OPEN) return GZ_OK;"),
    ("host.c", "the listing: an unlisted lobby",
     "if (!h->cfg.listed || h->state < GZ_LOBBY_OPEN || h->state > GZ_LOBBY_SIGNING) return GZ_OK;",
     "if (h->state < GZ_LOBBY_OPEN || h->state > GZ_LOBBY_SIGNING) return GZ_OK;"),
    ("act.c", "ended: any stored bytes sent on as the cancel",
     "gz_lobby_decode_env(cancel, cancel_len, &m) != GZ_DEC_OK || m.kind != GZ_KIND_CANCEL ||\n        memcmp(m.scope, scope, 32) != 0)",
     "0)"),
    ("act.c", "a SEND without its link",
     "    a.u.send.link = *link;\n",
     ""),
]


def named_mutants(only_files):
    """The named mutants; each must apply to core/lobby's text exactly once."""
    gone = []
    for name, what, old, new in NAMED:
        text = open(f"{REPO}/core/lobby/{name}").read()
        if text.count(old) != 1:
            gone.append(f"{name}: {what} (found {text.count(old)} times)")
    if gone:
        sys.exit("named mutants that no longer apply exactly once:\n  " + "\n  ".join(gone))
    for name, what, old, new in NAMED:
        if only_files is None or name in only_files or "named" in only_files:
            yield (name, -1, "named: " + what, (old, new))


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
                    yield (name, i, f"{a.strip()} -> {b.strip()} @{at + 1}", line[:at] + b + line[at + len(a):])
                start = at + len(a)
        for mt in re.finditer(r"!(?!=)", body):
            yield (name, i, f"drop ! @{mt.start() + 1}", line[:mt.start()] + line[mt.start() + 1:])
        if '"' not in body and "[" not in body.split("=")[0]:
            for mt in re.finditer(r"(?<![\w.])(\d+)(u|ull|ul)?(?![\w.x])", body):
                v = int(mt.group(1))
                yield (name, i, f"{v} -> {v + 1} @{mt.start(1) + 1}", line[:mt.start(1)] + str(v + 1) + line[mt.end(1):])
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


INC = ["-I", f"{REPO}/core/gazpacho/include", "-I", f"{REPO}/core/lobby/include", "-I", f"{REPO}/core/tree/include",
       "-I", f"{REPO}/sim",
       "-I", f"{SECP_SRC}/include"]
CC = ["gcc", "-std=gnu11", "-O1", "-w", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
MAINS = ["test_lobby_vectors", "test_lobby", "test_lobby_v2", "test_lobby_hostile", "test_lobby_sim", "fuzz_lobby",
         "fuzz_lobby_main", "fuzz_lobby_seq", "fuzz_lobby_seq_main", "model_driver"]
OBJ = f"{OUT}/obj"
FAST = ["gcc", "-std=gnu11", "-O2", "-w"]           # the simulator runs long: built without the checkers


def prebuild():
    """Everything a mutant does not touch is compiled once."""
    os.makedirs(OBJ, exist_ok=True)
    srcs = {f"lobby_{f[:-2]}": f"{REPO}/core/lobby/{f}" for f in FILES}
    srcs.update({"action": f"{REPO}/core/gazpacho/action.c", "runner": f"{REPO}/core/gazpacho/runner.c",
                 "rng": f"{REPO}/sim/rng.c"})
    srcs.update({f"tree_{t}": f"{REPO}/core/tree/{t}.c" for t in TREE})
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
    objs += [f"{OBJ}/action{sfx}", f"{OBJ}/runner{sfx}", f"{OBJ}/rng{sfx}"] + [f"{OBJ}/tree_{t}{sfx}" for t in TREE]
    main_obj = {"lobby_model_driver": "model_driver", "test_lobby_sim_fast": "test_lobby_sim"}.get(binary, binary)
    mains = [main_obj] + ({"fuzz_lobby": ["fuzz_lobby_main"], "fuzz_lobby_seq": ["fuzz_lobby_seq_main"]}.get(binary, []))
    return run((FAST if fast else CC) + [f"{OBJ}/{m}{sfx}" for m in mains] + objs + [SECP_LIB, "-o", out], work, 120) == 0


def one(job):
    k, (name, i, what, new) = job
    work = tempfile.mkdtemp(prefix="mut", dir=OUT)
    try:
        text = open(f"{REPO}/core/lobby/{name}").read()
        if i < 0:                                   # a named mutant: an exact piece of text
            old, repl = new
            open(f"{work}/{name}", "w").write(text.replace(old, repl))
        else:
            lines = text.split("\n")
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


def baseline():
    """The engine as it is must pass every test under the same build, or no kill means anything."""
    name = FILES[0]
    work = tempfile.mkdtemp(prefix="base", dir=OUT)
    try:
        shutil.copy(f"{REPO}/core/lobby/{name}", f"{work}/{name}")
        os.mkdir(f"{work}/q")
        if not build(work, name):
            sys.exit("baseline: core/lobby does not build")
        for t, cmd in enumerate(TESTS):
            binary = next(c for c in cmd if c.startswith("{q}/"))[4:]
            if not link(work, name, binary):
                sys.exit(f"baseline: {binary} does not link")
            r = run([c.format(q=f"{work}/q", repo=REPO) for c in cmd], work, 600)
            if r != 0:
                sys.exit(f"baseline: test {t} ({binary}) fails on the unmutated engine: {r}")
        print("baseline: every test passes on the unmutated engine", flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    os.makedirs(OUT, exist_ok=True)
    jobs = list(named_mutants(ONLY))
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
    baseline()
    log = open(f"{OUT}/results.txt", "w")
    counts = {"killed": 0, "SURVIVED": 0, "invalid": 0}
    by_test = [0] * len(TESTS)
    src = {f: open(f"{REPO}/core/lobby/{f}").read().split("\n") for f in FILES}
    with ThreadPoolExecutor(WORKERS) as ex:
        for k, name, i, what, res, t in ex.map(one, list(enumerate(jobs))):
            counts[res] += 1
            if t is not None:
                by_test[t] += 1
            where = src[name][i].strip() if i >= 0 else "(named)"
            # The line as the mutant has it, so that one of several matches on a
            # line is known without running it again (review A of PR 44, L6).
            now = (jobs[k][3].strip() or "(deleted)") if i >= 0 else "(named)"
            log.write(f"{res} {name}:{i + 1} {what} | {where} | now: {now}" +
                      (f" | test {t}" if t is not None else "") + "\n")
            log.flush()
    summary = (f"total {len(jobs)}: killed {counts['killed']}, survived {counts['SURVIVED']}, "
               f"invalid {counts['invalid']}; first kill by test: {by_test}")
    print(summary)
    log.write(summary + "\n")


main()
