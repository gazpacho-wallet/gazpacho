#!/usr/bin/env python3
"""Randomized model test of core/tree against the Python reference.

The reference is tools/spec-vectors.py itself: the functions that print the
vectors of terms.md (split_walk, funding_requirement, tlv, tagged_hash, ...)
and exit.md section X (x_leave_by, x_path_shape, ...). They are lifted out of
that file with the ast module and executed alone, so the slow module-level
vector printing never runs and the reference cannot drift from what the
specifications print.

Random shapes, member counts, amounts, heights, and complete terms records
(outer and current) are generated; each case is answered by the reference
and by tests/tree/tree_model_driver.c; every answer must agree exactly.
Records that the specification's bounds forbid are generated too, each with
the refusal the C decoder must give.

    python3 -I tests/tree/model_check.py DRIVER tools/spec-vectors.py [CASES] [SEED]

Standard library only.
"""
import ast
import hashlib
import random
import subprocess
import sys

FUNCS = {"tagged_hash", "bigsize", "tlv", "u8", "u16", "u32", "u64", "rng", "shape_bytes", "split_walk",
         "funding_requirement", "x_cltv_feeding", "x_path_timeouts", "x_h_leaf", "x_n_path",
         "x_last_safe_confirm", "x_leave_by", "x_step_due", "x_unlock_by", "x_vsize_tree", "x_path_shape"}
CONSTS = {"LEAF_PS", "X_STEP", "X_BURY", "X_ALLOW", "X_M_SAFE", "X_M_LAG", "X_M_SPIKE", "X_M", "X_M_HOST"}


def load_reference(path):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, path)
    body, found = [], set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in FUNCS:
            body.append(node)
            found.add(node.name)
        elif isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) and t.id in CONSTS for t in node.targets):
            body.append(node)
            found.update(t.id for t in node.targets)
    missing = (FUNCS | CONSTS) - found
    if missing:
        sys.exit("reference lacks: " + ", ".join(sorted(missing)))
    ns = {"hashlib": hashlib}
    exec(compile(ast.Module(body=body, type_ignores=[]), path, "exec"), ns)
    return ns


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    driver, ref_path = sys.argv[1], sys.argv[2]
    cases = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    R = load_reference(ref_path)
    rnd = random.Random(seed)
    SIGNET = bytes.fromhex("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")[::-1]
    HOST = bytes.fromhex("02b8dd739a5d2b0709fec5cea4e84eb7811b904ccf871c77a1a78b1e3473349156")

    def levels_of(interior):
        return list(interior) + [R["LEAF_PS"]]

    def rand_levels():
        k = rnd.choice([0, 0, 1, 1, 1, 2, 2, 3])
        return levels_of([rnd.randint(4, 15) for _ in range(k)])

    def split(levels, n):
        try:
            return [d for d, _ in R["split_walk"](levels, n)]
        except ValueError:
            return None

    def L(levels):
        return ",".join(str(x) for x in levels)

    def shape_valid(entries):
        prev = 2
        for mx, interior, _ in entries:
            for n in range(prev + 1, mx + 1):
                if split(levels_of(interior), n) is None:
                    return False
            prev = mx
        return True

    def rand_shapes(target):
        for _ in range(200):
            entries, prev = [], 2
            for _ in range(rnd.randint(1, 3)):
                lo = prev + 1
                if lo > 1000:
                    break
                mx = rnd.randint(lo, min(1000, lo + rnd.choice([0, 3, 12, 60, 300])))
                k = 0 if not entries else rnd.choice([0, 1, 1, 2])
                entries.append((mx, [rnd.randint(4, 15) for _ in range(k)], 3))
                prev = mx
            if entries[-1][0] < target:
                entries.append((max(target, prev + 1), [], 3))
            if shape_valid(entries):
                return entries
        return [(max(target, 3), [], 3)]

    def utf8_text(maxbytes):
        alphabet = "abcXYZ 09-é€😀ß"
        while True:
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, maxbytes)))
            b = s.encode()
            if 1 <= len(b) <= maxbytes:
                return b

    def rand_terms():
        target = rnd.choice([3, 4, 8, 16, rnd.randint(3, 300)])
        shapes = rand_shapes(target)
        budget_lo = rnd.randint(60_000, 600_000)
        recs = [(2, SIGNET if rnd.random() < 0.8 else bytes(rnd.getrandbits(8) for _ in range(32)))]
        if rnd.random() < 0.3:
            recs.append((3, utf8_text(32)))
        recs.append((4, HOST))
        if rnd.random() < 0.3:
            recs.append((5, utf8_text(280)))
        recs += [
            (6, bytes(rnd.getrandbits(8) for _ in range(16))),
            (8, R["u8"](rnd.randint(1, 4))),
            (10, R["u16"](target)),
            (12, R["u16"](rnd.randint(3, target))),
            (14, R["u64"](rnd.getrandbits(64))),
            (16, R["u8"](rnd.randint(0, 1))),
            (18, R["u32"](rnd.randint(1_000, 600_000))),
            (20, R["u32"](rnd.randint(budget_lo, 86_400_000))),
            (22, R["u32"](budget_lo)),
            (24, R["shape_bytes"](shapes)),
            (26, R["u32"](rnd.randint(1, 52_560))),
            (28, R["u32"](rnd.randint(1, 52_560))),
            (30, R["u64"](rnd.choice([546, rnd.randint(546, 10**6), rnd.randint(546, 2_100_000_000_000_000)]))),
            (32, R["u32"](rnd.choice([1, 100, rnd.randint(1, 1_000_000)]))),
            (34, R["u8"](rnd.randint(0, 7))),
        ]
        unknown = False
        if rnd.random() < 0.2:
            t = rnd.choice([35, 37, 41, 63])
            recs.append((t, utf8_text(8)))
            unknown = True
        ranges = {}
        for t, ceil in ((64, 2_100_000_000_000_000), (66, 4_294_967_295), (68, 4_294_967_295)):
            lo = rnd.randint(0, ceil)
            hi = rnd.choice([lo, rnd.randint(lo, ceil), ceil])
            ranges[t] = (lo, hi)
        if rnd.random() < 0.2:
            t = rnd.choice([65, 67, 69, 101, 127])
            lo = rnd.getrandbits(40)
            ranges[t] = (lo, lo + rnd.getrandbits(20))
        for t in sorted(ranges):
            recs.append((t, R["rng"](*ranges[t])))
        recs.sort(key=lambda r: r[0])
        return recs, shapes, ranges, unknown

    lines, expect, what = [], [], []

    def ask(cmd, answer, label):
        lines.append(cmd)
        expect.append(answer)
        what.append(label)

    for _ in range(cases):
        kind = rnd.random()
        if kind < 0.35:
            levels = rand_levels()
            n = rnd.choice([rnd.randint(1, 40), rnd.randint(3, 300), rnd.randint(3, 1000)])
            d = split(levels, n)
            ask(f"split {L(levels)} {n}", "refuse" if d is None else "ok " + ",".join(map(str, d)), "split")
            if d is None:
                continue
            ch = rnd.choice([546, rnd.randint(546, 10**6), rnd.randint(546, 2_100_000_000_000_000)])
            fee = rnd.choice([0, 17, 26, rnd.randint(0, 731_000)])
            r = R["funding_requirement"](levels, n, ch, fee, 240)
            ask(f"req {L(levels)} {n} {ch} {fee}", "refuse" if r >= 2**64 else str(r), "req")
            m = rnd.randrange(n)
            pd, outs = R["x_path_shape"](levels, n, m)
            ask(f"path {L(levels)} {n} {m}", f"{pd} " + ",".join(map(str, outs)), "path")
        elif kind < 0.55:
            E = rnd.choice([rnd.randint(0, 200), rnd.randint(0, 2_000_000)])
            d = rnd.randint(1, 12)
            nm = rnd.randint(1, d + 3)
            i = rnd.randint(1, nm)
            late = rnd.randint(0, 1)
            ts = ",".join("-" if h is None else str(h) for _, h in R["x_path_timeouts"](E, d))
            ans = " ".join(str(x) for x in (R["x_h_leaf"](E, d), R["x_last_safe_confirm"](E, d), R["x_leave_by"](E, d, nm),
                                            R["x_step_due"](E, d, i, nm), R["x_unlock_by"](E, d, nm, bool(late))))
            ask(f"exit {E} {d} {nm} {i} {late}", ans + " " + ts, "exit")
            k = rnd.randint(1, 15)
            ask(f"vsize {k}", str(R["x_vsize_tree"](k)), "vsize")
        else:
            recs, shapes, ranges, unknown = rand_terms()
            outer = R["tlv"](recs)
            digest = R["tagged_hash"]("gazpacho/terms/outer", outer).hex()
            ask(f"outer {outer.hex()}", f"ok {digest} " + ("-" if False else (outer.hex() if not unknown else "*")), "outer")
            # The tree terms.md 4.2 derives, for a member count the table covers.
            top = min(shapes[-1][0], 256)
            n = rnd.randint(3, top)
            entry = next(e for e in shapes if e[0] >= n)
            levels = levels_of(entry[1])
            depths = split(levels, n)
            outs = set()
            for m in range(n):
                outs.update(R["x_path_shape"](levels, n, m)[1])
            V = R["x_vsize_tree"](max(outs))
            rate = int.from_bytes(dict(recs)[32], "big")
            ch = int.from_bytes(dict(recs)[30], "big")
            fee = -(-rate * V // 1000)
            Rr = R["funding_requirement"](levels, n, ch, fee, 240)
            want = f"{max(depths)} {V} {fee} {Rr}" if Rr < 2**64 else "params_4"
            ask(f"params {outer.hex()} {n}", want, "params")
            # A current record for it.
            vals = {t: rnd.randint(lo, hi) for t, (lo, hi) in ranges.items()}
            version = rnd.choice([1, 2, rnd.getrandbits(32) or 1])
            od = bytes.fromhex(digest)
            cur = R["tlv"]([(2, od), (4, R["u32"](version))] + [(t, R["u64"](v)) for t, v in sorted(vals.items())])
            cd = R["tagged_hash"]("gazpacho/terms/current", cur).hex()
            ask(f"current {outer.hex()} {cur.hex()}", f"ok {cd} {cur.hex()}", "current")
            # One value past its range: refused.
            t = rnd.choice(sorted(ranges))
            lo, hi = ranges[t]
            if hi < 2**64 - 1:
                bad = dict(vals)
                bad[t] = hi + 1
                curb = R["tlv"]([(2, od), (4, R["u32"](version))] + [(k, R["u64"](v)) for k, v in sorted(bad.items())])
                ask(f"current {outer.hex()} {curb.hex()}", "adj_value " + R["tagged_hash"]("gazpacho/terms/current", curb).hex() + " -", "current-bad")
            # A record made non-minimal (BigSize length written fd00xx): refused.
            i = rnd.randrange(len(recs))
            t, v = recs[i]
            if len(v) < 0xfd:
                raw = b"".join(R["bigsize"](tt) + (b"\xfd" + len(vv).to_bytes(2, "big") if j == i else R["bigsize"](len(vv))) + vv
                               for j, (tt, vv) in enumerate(recs))
                ask(f"outer {raw.hex()}", "not_minimal " + R["tagged_hash"]("gazpacho/terms/outer", raw).hex() + " -", "nonminimal")
            # Two records swapped: refused for order.
            if len(recs) > 3:
                j = rnd.randrange(len(recs) - 1)
                sw = recs[:j] + [recs[j + 1], recs[j]] + recs[j + 2:]
                raw = b"".join(R["bigsize"](tt) + R["bigsize"](len(vv)) + vv for tt, vv in sw)
                ask(f"outer {raw.hex()}", "order " + R["tagged_hash"]("gazpacho/terms/outer", raw).hex() + " -", "order")

    proc = subprocess.run([driver], input="\n".join(lines) + "\n", capture_output=True, text=True, check=False)
    got = proc.stdout.splitlines()
    if proc.returncode != 0 or len(got) != len(lines):
        print(f"FAIL: driver exit {proc.returncode}, {len(got)} answers for {len(lines)} questions")
        print(proc.stderr[:2000])
        return 1
    bad = 0
    kinds = {}
    for cmd, want, g, label in zip(lines, expect, got, what):
        kinds[label] = kinds.get(label, 0) + 1
        ok = g == want
        if label == "outer" and want.endswith(" *"):
            ok = g.rsplit(" ", 1)[0] == want.rsplit(" ", 1)[0]   # unknown odd types are not re-encoded
        if label == "outer" and not ok and g.split(" ")[0] != "ok":
            # A random record the Slice 1 column does not limit, but section 3 does?
            pass
        if not ok:
            bad += 1
            if bad <= 10:
                print(f"MISMATCH {label}: {cmd[:160]}\n  reference {want[:200]}\n  C         {g[:200]}")
    print("cases by kind: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())))
    if bad:
        print(f"RESULT: FAIL ({bad} of {len(lines)} answers differ; seed {seed})")
        return 1
    print(f"RESULT: PASS ({len(lines)} answers agree; seed {seed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
