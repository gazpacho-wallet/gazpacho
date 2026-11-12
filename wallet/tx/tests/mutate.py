#!/usr/bin/env python3
"""Mutation run for wallet/tx/src (checklist items 7 and 8).

usage: mutate.py REPO BUILD [--jobs N] [--sanitize] [--labels FILE]

--sanitize builds the mutants with AddressSanitizer and UBSan, so that a
mutant which only reads out of bounds is seen.  --labels runs only the
mutants whose labels (as printed) are listed in FILE, one per line.

REPO is the source tree, BUILD a configured and built tree of it (for the
prebuilt key library, imported code and secp256k1).  Every mutant changes one
thing in one library source file: a comparison, a logical operator, an
arithmetic operator, an integer constant, a returned error code, a negation,
or a whole one-line statement removed.  Then the four test programs and the
tool test are rebuilt against the mutant and run; a mutant that no test
notices SURVIVES.  Mutants that do not compile are counted apart, not as
caught.  The named "rule removed" runs at the top are reported first.
Exit status 0 when it ran; survivors are reported, not failed on, because some
are equivalent mutants that a person must judge.
"""
import concurrent.futures as cf
import os
import re
import shutil
import subprocess
import sys
import tempfile

SRC = ["wallet/tx/src/tx.c", "wallet/tx/src/sighash.c", "wallet/tx/src/funding.c"]

# (name, file, text, replacement): each safety rule removed.
RULES = [
    ("mainnet-name", "tx.c", 'if (strcmp(name, "mainnet") == 0) return GZT_ERR_MAINNET;', ""),
    ("rate-above-ceiling", "funding.c",
     "if (fee.rate.sat_per_kvb > fee.ceiling.sat_per_kvb) return GZT_ERR_FEE_CEILING;", ""),
    ("real-rate-ceiling", "funding.c", "if (paid > gzt_fee_for_vsize(fee.ceiling, vs_nc)) {",
     "if (0) {"),
    ("server-rate-ceiling", "tx.c",
     "if (server_sat_per_kvb > ceiling.sat_per_kvb) return GZT_ERR_FEE_CEILING;", ""),
    ("dust-payment", "funding.c",
     "if (amount < gzt_dust_limit(dest, dest_len)) return GZT_ERR_DUST;", ""),
    ("dust-change", "funding.c", "if (total >= amount + fee_c + P2TR_DUST) {",
     "if (total >= amount + fee_c) {"),
    ("witness-destination", "funding.c",
     "if (!gzt_is_witness_program(dest, dest_len)) return GZT_ERR_SCRIPT;", ""),
    ("duplicate-coins", "funding.c",
     "if (coins[j].vout == coins[i].vout && memcmp(coins[j].txid, coins[i].txid, 32) == 0)",
     "if (0)"),
    ("sign-key-matches-script", "sighash.c",
     "if (memcmp(key, s->script + 2, 32) != 0) return GZT_ERR_KEY;", ""),
    ("verify-after-sign", "sighash.c",
     "if (!secp256k1_schnorrsig_verify(ctx, sig, hash, 32, &want)) {", "if (0) {"),
    ("coin-script-is-its-key", "funding.c",
     "if (memcmp(out.script_pubkey, c->script, P2TR_LEN) != 0) {", "if (0) {"),
    ("change-not-a-spent-index", "funding.c",
     "if (coins[i].change == 1 && coins[i].index == req->change_index) return GZT_ERR_ARG;", ""),
    ("release-needs-txid", "funding.c",
     "if (!gzw_ct_equal(expect_txid, f->info.txid, 32)) return GZT_ERR_STATE;", ""),
    ("release-needs-build", "funding.c",
     "if (f->priv_state != 1) return GZT_ERR_STATE;", ""),
    ("wipe-on-failure", "funding.c", "    if (e) gzt_funding_wipe(out);\n", "\n"),
    ("parse-trailing-bytes", "tx.c", "if (r->pos != r->len) return GZT_ERR_PARSE;", ""),
    ("parse-minimal-size", "tx.c", "return *v >= min;", "return 1;"),
    ("parse-superfluous-witness", "tx.c",
     "if (!has_witness(tx)) return GZT_ERR_PARSE; /* superfluous witness record */", ""),
    ("parse-max-money", "tx.c", "if (sum > GZT_MAX_MONEY) return GZT_ERR_PARSE;", ""),
    ("parse-length-in-bounds", "tx.c", "if (n > r->len - r->pos) return GZT_ERR_PARSE;", ""),
    ("signed-size-is-fee-size", "funding.c",
     "if (e || vsize != sel->vsize || memcmp(txid2, f->info.txid, 32) != 0) return GZT_ERR_INTERNAL;",
     "if (e) return GZT_ERR_INTERNAL;"),
]

OPS = [(r"==", "!="), (r"!=", "=="), (r"(?<![<>=!-])<(?![<=])", "<="), (r"<=", "<"),
       (r"(?<![-<>=])>(?![>=])", ">="), (r">=", ">"), (r"&&", "||"), (r"\|\|", "&&"),
       (r" \+ ", " - "), (r" - ", " + "), (r" \* ", " / "), (r"\+\+", "--"),
       (r"\(!(?!=)", "("), (r"return GZT_ERR_\w+;", "return GZT_OK;"),
       (r"return 1;", "return 0;"), (r"return 0;", "return 1;")]
CONST = re.compile(r"(?<![\w.])(0x[0-9a-fA-F]+|\d+)(u|U|ULL)?(?![\w.])")
SKIP = re.compile(r'^\s*(#|/\*|\*|//|case GZT_\w+: return ")|^\s*$')
DELETABLE = re.compile(r"^\s*(if \(.*\) (return|continue|break)[^;]*;|[a-z_][\w.\->\[\]]*(\(.*\)| [-+*/|&^]?= .*);)\s*$")


def mutants():
    out = []
    for name, f, old, new in RULES:
        out.append(("rule " + name, "wallet/tx/src/" + f, old, new, None))
    for path in SRC:
        lines = open(os.path.join(REPO, path)).read().split("\n")
        in_comment = False
        for i, line in enumerate(lines):
            if "/*" in line and "*/" not in line:
                in_comment = True
            if in_comment:
                in_comment = "*/" not in line
                continue
            if SKIP.match(line) or "#define" in line:
                continue
            code = re.sub(r'"[^"]*"', lambda m: "\0" * len(m.group(0)), line.split("/*")[0])
            for pat, rep in OPS:
                for m in re.finditer(pat, code):
                    new = line[:m.start()] + re.sub(pat, rep, line[m.start():m.end()]) + line[m.end():]
                    out.append(("%s:%d %s" % (path, i + 1, rep.strip()), path, line, new, i))
            for m in CONST.finditer(code):
                v = m.group(1)
                nv = (hex(int(v, 16) + 1) if v.startswith("0x") else str(int(v) + 1))
                new = line[:m.start(1)] + nv + line[m.end(1):]
                out.append(("%s:%d const %s->%s" % (path, i + 1, v, nv), path, line, new, i))
            if DELETABLE.match(code):
                out.append(("%s:%d delete" % (path, i + 1), path, line, "", i))
    return out


def sh(cmd, cwd, timeout=300):
    try:
        return subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True,
                              timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return "timeout"


def run(m):
    label, path, old, new, line_no = m
    work = tempfile.mkdtemp(prefix="mut-", dir=SCRATCH)
    try:
        src = os.path.join(work, "src")
        os.makedirs(src)
        for p in SRC:
            shutil.copy(os.path.join(REPO, p), src)
        f = os.path.join(src, os.path.basename(path))
        text = open(f).read()
        if line_no is None:
            if old not in text:
                return label, "NOT APPLIED"
            text = text.replace(old, new, 1)
        else:
            lines = text.split("\n")
            if lines[line_no] != old:
                return label, "NOT APPLIED"
            lines[line_no] = new
            text = "\n".join(lines)
        open(f, "w").write(text)
        c = sh("gcc %s -c src/tx.c src/sighash.c src/funding.c -I%s/wallet/tx/src && "
               "ar rcs libtx.a tx.o sighash.o funding.o" % (CFLAGS, REPO), work)
        if c != 0:
            return label, "BUILD ERROR"
        links = []
        for t in ("test_tx_vectors", "test_tx", "fuzz_tx_parse", "test_tx_faults"):
            extra = "-Wl,--wrap=secp256k1_schnorrsig_sign32" if t == "test_tx_faults" else ""
            links.append("gcc %s %s/objs/%s.o libtx.a %s %s -o %s" % (CFLAGS, SCRATCH, t, LIBS, extra, t))
        links.append("gcc %s %s/objs/main.o libtx.a %s -o gz-wallet-tx" % (CFLAGS, SCRATCH, LIBS))
        if sh(" && ".join(links), work) != 0:
            return label, "BUILD ERROR"
        caught = []
        for t, cmd in (("vectors", "./test_tx_vectors"), ("unit", "./test_tx"),
                       ("fuzz", "./fuzz_tx_parse 20000"), ("faults", "./test_tx_faults"),
                       ("tool", "sh %s/wallet/tx/tests/test_tool.sh ./gz-wallet-tx tool" % REPO)):
            r = sh(cmd + " >/dev/null 2>&1", work, 120)
            if r != 0:
                caught.append(t + ("(timeout)" if r == "timeout" else ""))
        return label, ("caught by " + ",".join(caught)) if caught else "SURVIVED"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    global REPO, SCRATCH, CFLAGS, LIBS
    args = sys.argv[1:]
    jobs = 4
    if "--jobs" in args:
        i = args.index("--jobs")
        jobs = int(args[i + 1])
        del args[i:i + 2]
    labels = None
    if "--labels" in args:
        i = args.index("--labels")
        labels = set(l.strip() for l in open(args[i + 1]) if l.strip())
        del args[i:i + 2]
    san = "--sanitize" in args
    if san:
        args.remove("--sanitize")
    REPO, build = os.path.abspath(args[0]), os.path.abspath(args[1])
    SCRATCH = tempfile.mkdtemp(prefix="gzt-mutate-")
    secp = os.path.join(build, "_deps/secp256k1-zkp-src")
    for line in open(os.path.join(build, "CMakeCache.txt")):
        if line.startswith("FETCHCONTENT_SOURCE_DIR_SECP256K1-ZKP:") and line.split("=", 1)[1].strip():
            secp = line.split("=", 1)[1].strip()
    secp = os.path.join(secp, "include")
    CFLAGS = ("-std=gnu11 -O1 -w -I%s/wallet/include -I%s/wallet/tx/include -I%s/wallet/tx/vectors "
              "-I%s" % (REPO, REPO, REPO, secp))
    if san:
        CFLAGS += " -fsanitize=address,undefined -fno-sanitize-recover=undefined"
    libs = []
    for name in ("libgazpacho_wallet_keys.a", "libgazpacho_superscalar.a", "libsecp256k1.a"):
        found = subprocess.run("find %s -name %s | head -1" % (build, name), shell=True,
                               capture_output=True, text=True).stdout.strip()
        libs.append(found)
    LIBS = " ".join(libs) + " -lcrypto"
    os.makedirs(SCRATCH + "/objs")
    for t in ("test_tx_vectors", "test_tx", "fuzz_tx_parse", "test_tx_faults"):
        if sh("gcc %s -c %s/wallet/tx/tests/%s.c -o objs/%s.o" % (CFLAGS, REPO, t, t), SCRATCH):
            sys.exit("cannot compile " + t)
    if sh("gcc %s -c %s/tools/gz-wallet-tx/main.c -o objs/main.o" % (CFLAGS, REPO), SCRATCH):
        sys.exit("cannot compile the tool")
    base = run(("baseline", SRC[0], "", "", None))
    if base[1] != "SURVIVED":
        sys.exit("the unmutated code fails its tests: " + base[1])
    ms = [m for m in mutants() if labels is None or m[0] in labels]
    counts = {}
    survivors = []
    with cf.ThreadPoolExecutor(jobs) as ex:
        for label, result in ex.map(run, ms):
            key = "caught" if result.startswith("caught") else result
            counts[key] = counts.get(key, 0) + 1
            if label.startswith("rule ") or result in ("SURVIVED", "NOT APPLIED"):
                print("%-60s %s" % (label, result), flush=True)
            if result == "SURVIVED":
                survivors.append(label)
    print("mutants %d: %s" % (len(ms), ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
    shutil.rmtree(SCRATCH, ignore_errors=True)


if __name__ == "__main__":
    main()
