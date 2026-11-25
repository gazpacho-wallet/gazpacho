#!/usr/bin/env python3
"""Test for tools/check-signer-boundary.sh: what counts as a use, and the three modes.

    python3 -I tests/tools/test_check_signer_boundary.py

Builds a throwaway tree with the real symbol list and C files that use, and
only seem to use, signer-only symbols, and checks the listing, the counts and
the verdict of --report, --no-growth and --fail against allow lists that
match, miss a use, or name too many. Standard library only; needs sh, awk,
find and sort.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CHECK = os.path.join(ROOT, "tools", "check-signer-boundary.sh")
SYMBOLS = os.path.join(ROOT, "tools", "signer-only-symbols.txt")
failures = []

USES = r'''
#include <secp256k1.h>
/* secp256k1_schnorrsig_sign32 in a comment
   spanning lines: secp256k1_ecdh(ctx, out, p, sec) */
static const char *s = "secp256k1_keypair_create(ctx, &kp, sec)";
static const char c = '"'; // secp256k1_musig_partial_sign
int f(void) {
    secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, aux);   /* one */
    ok = secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &pk) && my_secp256k1_ecdh_x(1) && secp256k1_ecdhx(2);
    if (k->ports->keys.secret(k->ports->keys.ctx, 1, 2, sec) != 1) return 0;   /* hook:secret */
    if (c.sign == NULL || c.signature) return 0;              /* not a use */
    x = secp256k1_keypair_create(a, b, c) + secp256k1_keypair_create(a, b, c);   /* two on one line */
    return 0;
}
typedef struct { int (*sign)(void *ctx, const uint8_t msg32[32], uint8_t sig[64]); int (*secret_count)(void); } hooks_t;
static hooks_t h = { .sign = port_sign };
'''


def tree():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "tools"))
    shutil.copy(SYMBOLS, os.path.join(d, "tools", "signer-only-symbols.txt"))
    files = {
        "core/a.c": USES,
        "program/b.h": "int gzp_net_sign(int x);\n",
        "signer/s.c": "void f(void) { secp256k1_schnorrsig_sign32(0, 0, 0, 0, 0); }\n",
        "signer/tests/t.c": "void f(void) { secp256k1_ecdh(0, 0, 0, 0, 0, 0); }\n",
        "core/superscalar/src/m.c": "void f(void) { secp256k1_musig_partial_sign(0, 0, 0, 0, 0, 0); }\n",
        "build/x.c": "void f(void) { secp256k1_ecdh(0, 0, 0, 0, 0, 0); }\n",
        "docs/n.md": "secp256k1_ecdh\n",
        "tools/z.py": "secp256k1_ecdh()\n",
    }
    for rel, text in files.items():
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return d


WANT = {
    ("core/a.c", "secp256k1_schnorrsig_sign32"): 1,
    ("core/a.c", "secp256k1_keypair_create"): 2,
    ("core/a.c", "hook:secret"): 1,
    ("core/a.c", "hook:sign"): 2,
    ("core/a.c", "port_sign"): 1,
    ("program/b.h", "gzp_net_sign"): 1,
}


# The check lists the files git tracks (review B of #71, M4), so every fixture
# is a git work tree: everything is tracked but the paths named here, which
# stand for build output.
UNTRACKED = {}
GIT_ENV = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", HOME=tempfile.gettempdir())


def git(d, *args):
    subprocess.run(["git", "-c", "init.defaultBranch=main", "-C", d] + list(args), check=True,
                   capture_output=True, env=GIT_ENV)


def run(d, *args):
    if not os.path.isdir(os.path.join(d, ".git")):
        git(d, "init", "-q")
    git(d, "add", "-A")
    for p in UNTRACKED.get(d, ()):
        git(d, "rm", "-r", "-q", "--cached", "--ignore-unmatch", p)
    r = subprocess.run(["sh", CHECK, "--root", d] + list(args), capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def write_allow(d, entries):
    path = os.path.join(d, "allow.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("# comment\n\n")
        for (fn, sym), n in sorted(entries.items()):
            f.write("%s\t%s\t%d\n" % (fn, sym, n))
    return path


def expect(name, cond, out=""):
    if cond:
        print("ok   %s" % name)
    else:
        failures.append(name)
        print("FAIL %s\n%s" % (name, out))


d = tree()
UNTRACKED[d] = ("build",)   # build output: never tracked, never scanned

# --write-allow gives exactly the uses above: the listing is right.
code, out = run(d, "--write-allow", os.path.join(d, "written.txt"))
got = {}
with open(os.path.join(d, "written.txt"), encoding="utf-8") as f:
    for line in f:
        if line.startswith("#") or not line.strip():
            continue
        fn, sym, n = line.rstrip("\n").split("\t")
        got[(fn, sym)] = int(n)
expect("the uses are exactly those in code outside signer/", got == WANT, "%r\n%s" % (got, out))
expect("report mode exits 0 with uses and no allow list", code == 0, out)
expect("the report names the totals", "8 uses of signer-only symbols outside signer/, in 2 files" in out, out)
expect("the report shows each file", "  core/a.c: 7" in out and "  program/b.h: 1" in out, out)
expect("report mode shows growth", "GROWTH core/a.c: hook:secret used 1 times, allowed 0" in out, out)

# --fail: any use fails.
code, out = run(d, "--fail")
expect("--fail fails on any use", code == 1 and "FAIL" in out, out)

# --no-growth: an exact list passes; a missing use or a lower count is growth; an extra one is stale.
allow = write_allow(d, WANT)
code, out = run(d, "--no-growth", "--allow", allow)
expect("--no-growth passes with the exact list", code == 0 and "GROWTH" not in out and "STALE" not in out, out)
code, out = run(d, "--no-growth", "--allow", os.path.join(d, "written.txt"))
expect("--no-growth passes with the written list", code == 0, out)
fewer = dict(WANT)
del fewer[("program/b.h", "gzp_net_sign")]
code, out = run(d, "--no-growth", "--allow", write_allow(d, fewer))
expect("--no-growth fails on a new use", code == 1 and "GROWTH program/b.h: gzp_net_sign" in out, out)
lower = dict(WANT)
lower[("core/a.c", "secp256k1_keypair_create")] = 1
code, out = run(d, "--no-growth", "--allow", write_allow(d, lower))
expect("--no-growth fails on a higher count", code == 1 and "GROWTH core/a.c: secp256k1_keypair_create used 2" in out, out)
more = dict(WANT)
more[("core/a.c", "secp256k1_ecdh")] = 1
code, out = run(d, "--no-growth", "--allow", write_allow(d, more))
expect("--no-growth fails on a stale line", code == 1 and "STALE core/a.c: secp256k1_ecdh" in out, out)
higher = dict(WANT)
higher[("core/a.c", "hook:sign")] = 3
code, out = run(d, "--no-growth", "--allow", write_allow(d, higher))
expect("--no-growth fails on a stale count", code == 1 and "STALE core/a.c: hook:sign allowed 3" in out, out)
code, out = run(d, "--allow", write_allow(d, more))
expect("report mode never fails", code == 0 and "STALE" in out, out)


# Review A of #71, M2: a new use together with its own allow-list line passes
# --no-growth, but not against the merge base's list.
base = os.path.join(d, "base.txt")
shutil.copy(write_allow(d, fewer), base)
grown = os.path.join(d, "grown.txt")
shutil.copy(write_allow(d, WANT), grown)
code, out = run(d, "--no-growth", "--allow", grown, "--base-allow", base)
expect("a new allow-list line fails against the merge base",
       code == 1 and "ALLOW-GROWTH program/b.h: gzp_net_sign is a new line" in out, out)
raised_base = dict(WANT)
raised_base[("core/a.c", "secp256k1_keypair_create")] = 1
raised = os.path.join(d, "raised.txt")
shutil.copy(write_allow(d, raised_base), raised)
code, out = run(d, "--no-growth", "--allow", grown, "--base-allow", raised)
expect("a raised count fails against the merge base",
       code == 1 and "ALLOW-GROWTH core/a.c: secp256k1_keypair_create raised from 1 to 2" in out, out)
same_base = os.path.join(d, "same.txt")
shutil.copy(grown, same_base)
code, out = run(d, "--no-growth", "--allow", grown, "--base-allow", same_base)
expect("the same list as the merge base passes", code == 0 and "no growth against the merge base" in out, out)
bigger = dict(WANT)
bigger[("core/a.c", "secp256k1_ecdh")] = 4
big = os.path.join(d, "big.txt")
shutil.copy(write_allow(d, bigger), big)
code, out = run(d, "--report", "--allow", grown, "--base-allow", big)
expect("a shrunk list passes against the merge base", code == 0, out)
# A tree with no use passes every mode.
clean = tempfile.mkdtemp()
os.makedirs(os.path.join(clean, "tools"))
shutil.copy(SYMBOLS, os.path.join(clean, "tools", "signer-only-symbols.txt"))
os.makedirs(os.path.join(clean, "core"))
with open(os.path.join(clean, "core", "ok.c"), "w", encoding="utf-8") as f:
    f.write("int f(void) { return secp256k1_schnorrsig_verify(0, 0, 0, 0, 0); }\n")
code, out = run(clean, "--fail")
expect("--fail passes with no use", code == 0 and "0 uses" in out, out)

# A bad symbol list is an error, not a pass.
with open(os.path.join(clean, "tools", "signer-only-symbols.txt"), "w", encoding="utf-8") as f:
    f.write("sym not-an-identifier\n")
code, out = run(clean)
expect("a bad symbol list is an error", code == 2, out)


# Review A of #71, M1: other file types, a top-level folder named like a build
# folder, a string continued with a backslash-newline, the added symbols.
m1 = tempfile.mkdtemp()
os.makedirs(os.path.join(m1, "tools"))
shutil.copy(SYMBOLS, os.path.join(m1, "tools", "signer-only-symbols.txt"))
for rel, text in {
    "core/c.inc": "secp256k1_ecdh(0, 0, 0, 0, 0, 0);\n",
    "core/d.cpp": "int f() { return secp256k1_ellswift_xdh(0, 0, 0, 0, 0, 0, 0, 0); }\n",
    "core/e.S": "call secp256k1_schnorrsig_sign32\n",
    "buildtools/g.c": "void f(void) { factory_sign_all(0, 0); }\n",
    "build/x.c": "void f(void) { factory_sign_all(0, 0); }\n",
    "build-asan/x.c": "void f(void) { factory_sign_all(0, 0); }\n",
    "core/h.c": 'const char *s = "abc\\\ndef"; void f(void) { secp256k1_ecdsa_sign(0, 0, 0, 0, 0, 0); }\n',
    "program/p.c": "int f(void) { return gzw_phrase_to_seed(0, 0, 0); }\n",
}.items():
    path = os.path.join(m1, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
UNTRACKED[m1] = ("build", "build-asan")
code, out = run(m1, "--write-allow", os.path.join(m1, "w.txt"))
got = {}
with open(os.path.join(m1, "w.txt"), encoding="utf-8") as f:
    for line in f:
        if not line.startswith("#") and line.strip():
            fn, sym, n = line.rstrip("\n").split("\t")
            got[(fn, sym)] = int(n)
WANT_M1 = {
    ("core/c.inc", "secp256k1_ecdh"): 1,
    ("core/d.cpp", "secp256k1_ellswift_xdh"): 1,
    ("core/e.S", "secp256k1_schnorrsig_sign32"): 1,
    ("buildtools/g.c", "factory_sign_all"): 1,
    ("core/h.c", "secp256k1_ecdsa_sign"): 1,
    ("program/p.c", "gzw_phrase_to_seed"): 1,
}
expect(".inc, .cpp, .S, buildtools/, a continued string and the added symbols are seen", got == WANT_M1,
       "%r\n%s" % (got, out))

# Review A of #71, H3: the fixed-aux test build named outside signer/, or a
# source of signer/ included elsewhere, fails in every mode.
for name, rel, text in [
    ("#define GZ_SG_VECTORS", "program/v.c", "#define GZ_SG_VECTORS 1\n#include \"gazpacho/signer.h\"\n"),
    ("#ifdef GZ_SG_VECTORS", "core/v.h", "#ifdef GZ_SG_VECTORS\n#endif\n"),
    ("a gz_sgv_ name", "program/v.c", "int f(void) { return gz_sgv_sign_envelope(0, 0, 0, 0, 0, 0, 0, 0); }\n"),
    ("the marker", "program/v.c", "extern const char gz_sg_vectors_build_never_ship[];\n"),
    ("#include of signer.c", "program/v.c", "#include \"../signer/signer.c\"\n"),
    ("#include of a signer .inc", "core/v.c", "#  include <signer/x.inc>\n"),
    ("GZ_SG_VECTORS in a CMake file", "program/CMakeLists.txt", "target_compile_definitions(x PRIVATE GZ_SG_VECTORS)\n"),
    # review A of #71, N1: the build-flag routes
    ("-DGZ_SG_VECTORS in target_compile_options", "program2/CMakeLists.txt",
     "add_executable(prog2 main.c)\ntarget_compile_options(prog2 PRIVATE -DGZ_SG_VECTORS)\n"),
    ("-DGZ_SG_VECTORS=1 in CMAKE_C_FLAGS", "CMakeLists.txt",
     "set(CMAKE_C_FLAGS \"${CMAKE_C_FLAGS} -DGZ_SG_VECTORS=1\")\n"),
    ("a flag in a .cmake file", "cmake/flags.cmake", "add_compile_definitions(GZ_SG_VECTORS)\n"),
    ("an ALIAS of the vectors build", "program/CMakeLists.txt", "add_library(sv ALIAS gazpacho_signer_vectors)\n"),
    ("$<TARGET_FILE:gazpacho_signer_vectors>", "program/CMakeLists.txt",
     "target_link_libraries(p PRIVATE $<TARGET_FILE:gazpacho_signer_vectors>)\n"),
    ("signer sources listed in a build file", "program2/CMakeLists.txt",
     "add_executable(prog2 main.c ../signer/signer.c ../signer/policy.c)\n"),
    ("a signer source by variable", "core/CMakeLists.txt", "set(S ${CMAKE_SOURCE_DIR}/signer/signer.c)\n"),
    ("gz_sg##v_ token pasting", "program/t.c", "#define V(x) gz_sg##v_##x\nint f(void) { return V(sign_envelope)(0); }\n"),
    ("## gz_sg token pasting", "program/t.c", "#define W(x) x ## gz_sgv\n"),
]:
    hd = tempfile.mkdtemp()
    os.makedirs(os.path.join(hd, "tools"))
    shutil.copy(SYMBOLS, os.path.join(hd, "tools", "signer-only-symbols.txt"))
    path = os.path.join(hd, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    for mode in ("--report", "--no-growth"):
        code, out = run(hd, mode)
        expect("%s fails %s" % (name, mode), code == 1 and "HARD %s:" % rel in out, out)
# ... but a comment that names it is no use, and the header's own name is fine
hd = tempfile.mkdtemp()
os.makedirs(os.path.join(hd, "tools"))
shutil.copy(SYMBOLS, os.path.join(hd, "tools", "signer-only-symbols.txt"))
os.makedirs(os.path.join(hd, "program"))
with open(os.path.join(hd, "program", "ok.c"), "w", encoding="utf-8") as f:
    f.write("/* GZ_SG_VECTORS gz_sgv_x */\n#include \"gazpacho/signer.h\"\n")
with open(os.path.join(hd, "CMakeLists.txt"), "w", encoding="utf-8") as f:
    f.write("# GZ_SG_VECTORS and gazpacho_signer_vectors in a comment\nadd_subdirectory(signer)\n"
            "include(${CMAKE_CURRENT_SOURCE_DIR}/signer/vectors_guard.cmake)\n"
            "add_executable(x core/signing/signing.c)\n")
code, out = run(hd, "--report")
expect("a comment naming the test build is not a hard finding", code == 0 and "HARD" not in out, out)

# Review B of #71, M4: a tracked build-* folder, splicing, a computed include,
# more file types, digit separators and the SuperScalar signing functions.
m4 = tempfile.mkdtemp()
os.makedirs(os.path.join(m4, "tools"))
shutil.copy(SYMBOLS, os.path.join(m4, "tools", "signer-only-symbols.txt"))
for rel, text in {
    "build-helpers/d.c": "void f(void) { secp256k1_ecdsa_sign(0, 0, 0, 0, 0, 0); }\n",
    "core/s.c": "int f(void) { return secp256k1_schnorrsig_si\\\ngn32(0, 0, 0, 0, 0); }\n",
    "core/x.cxx": "int f() { return secp256k1_ecdh(0, 0, 0, 0, 0, 0); }\n",
    "core/y.hpp": "inline int f() { return secp256k1_ecdh(0, 0, 0, 0, 0, 0); }\n",
    "core/z.hh": "inline int f() { return secp256k1_ecdh(0, 0, 0, 0, 0, 0); }\n",
    "core/w.s": "call secp256k1_ecdh\n",
    "core/sep.c": "int a = 1'0; void f(void) { secp256k1_keypair_create(0, 0, 0); } int b = 2'0;\n",
    "core/ch.c": "char c = 'x'; const char *s = \"secp256k1_ecdh\"; /* factory_sign_node */\n",
    "core/sq.c": "void f(void) { channel_sign_commitment(0); factory_sign_node(0); adaptor_create_turnover_presig(0);\n"
                 "  channel_derive_privkey(0); bolt11_encode(0); }\n",
    "build/y.c": "void f(void) { secp256k1_ecdh(0, 0, 0, 0, 0, 0); }\n",
}.items():
    path = os.path.join(m4, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
UNTRACKED[m4] = ("build",)
code, out = run(m4, "--write-allow", os.path.join(m4, "w.txt"))
got = {}
with open(os.path.join(m4, "w.txt"), encoding="utf-8") as f:
    for line in f:
        if not line.startswith("#") and line.strip():
            fn, sym, n = line.rstrip("\n").split("\t")
            got[(fn, sym)] = int(n)
WANT_M4 = {
    ("build-helpers/d.c", "secp256k1_ecdsa_sign"): 1,
    ("core/s.c", "secp256k1_schnorrsig_sign32"): 1,
    ("core/x.cxx", "secp256k1_ecdh"): 1,
    ("core/y.hpp", "secp256k1_ecdh"): 1,
    ("core/z.hh", "secp256k1_ecdh"): 1,
    ("core/w.s", "secp256k1_ecdh"): 1,
    ("core/sep.c", "secp256k1_keypair_create"): 1,
    ("core/sq.c", "channel_sign_commitment"): 1,
    ("core/sq.c", "factory_sign_node"): 1,
    ("core/sq.c", "adaptor_create_turnover_presig"): 1,
    ("core/sq.c", "channel_derive_privkey"): 1,
    ("core/sq.c", "bolt11_encode"): 1,
}
expect("a tracked build-* folder, a spliced name, .cxx/.hpp/.hh/.s, digit separators and SuperScalar are seen",
       got == WANT_M4, "%r\n%s" % (got, out))

for name, rel, text in [
    ("a tracked build-* folder's build file", "build-helpers/CMakeLists.txt",
     "add_library(x STATIC ../signer/signer.c)\ntarget_compile_definitions(x PRIVATE GZ_SG_VECTORS)\n"),
    ("a computed #include", "program/inc.c", "#define SRC \"../signer/signer.c\"\n#include SRC\n"),
    ("GZ_SG_VECTORS spliced across lines", "program/def.c", "#define GZ_SG_VECT\\\nORS 1\n"),
    ("-DGZ_SG_VECTORS in a workflow", ".github/workflows/release.yml",
     "jobs:\n  b:\n    steps:\n      - run: cmake -B b -DCMAKE_C_FLAGS=-DGZ_SG_VECTORS\n"),
    ("CFLAGS in a shell script", "tools/release.sh", "CFLAGS=-DGZ_SG_VECTORS make\n"),
    ("a CMake preset", "CMakePresets.json", "{\"configurePresets\": [{\"cacheVariables\": {\"CMAKE_C_FLAGS\": \"-DGZ_SG_VECTORS\"}}]}\n"),
    ("a Dockerfile", "Dockerfile", "RUN cmake -B b -DCMAKE_C_FLAGS=-DGZ_SG_VECTORS\n"),
]:
    hd = tempfile.mkdtemp()
    os.makedirs(os.path.join(hd, "tools"))
    shutil.copy(SYMBOLS, os.path.join(hd, "tools", "signer-only-symbols.txt"))
    path = os.path.join(hd, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    code, out = run(hd, "--report")
    expect("%s fails --report" % name, code == 1 and "HARD %s:" % rel in out, out)

# Review A of #71, re-review: the symbol list may only grow against the merge base.
sb = tempfile.mkdtemp()
os.makedirs(os.path.join(sb, "tools"))
shutil.copy(SYMBOLS, os.path.join(sb, "tools", "signer-only-symbols.txt"))
base_syms = os.path.join(sb, "base-symbols.txt")
shutil.copy(SYMBOLS, base_syms)
with open(SYMBOLS, encoding="utf-8") as f:
    cur = f.read()
with open(os.path.join(sb, "tools", "signer-only-symbols.txt"), "w", encoding="utf-8") as f:
    f.write(cur.replace("sym secp256k1_ecdh\n", ""))
code, out = run(sb, "--base-symbols", base_syms)
expect("a symbol removed against the merge base fails",
       code == 1 and "SYMBOL-REMOVED sym secp256k1_ecdh" in out, out)
with open(os.path.join(sb, "tools", "signer-only-symbols.txt"), "w", encoding="utf-8") as f:
    f.write("# a comment that moved\n" + cur + "sym some_new_signer_symbol\n")
code, out = run(sb, "--base-symbols", base_syms)
expect("the same symbols plus one, reordered comments, pass",
       code == 0 and "nothing removed against the merge base" in out, out)
if failures:
    print("RESULT: FAIL (%d)" % len(failures))
    sys.exit(1)
print("RESULT: PASS")
