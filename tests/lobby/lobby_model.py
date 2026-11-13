#!/usr/bin/env python3
"""Independent reference model of three lobby rules (LOBBY.md start rule,
messages.md 6.9 signer choice, terms.md 9 condition classes). Stdlib only.

Ambiguities and how this model reads them:
 1. choose: the cut to target happens once, before dropping. Seats cut off
    (beyond the target) are never brought back to refill gaps left by drops,
    even though LOBBY.md says extra arrivals "wait as standbys".
 2. choose: "fewer than the minimum remain" is checked once, after the drop
    loop ends; an empty result is None whenever minimum >= 1.
 3. choose: min_members compares with the count of chosen seats, host not
    counted, and a seat stays when min_members == count (only "exceeds" drops).
    All seats violating in a round are dropped together, then re-checked.
 4. start_rule: "at the deadline" is now_s >= deadline_s (equal counts as
    arrived); reaching target wins over the deadline; carry-over is not
    modelled (cancel is the default).
 5. classify: "bit profile" means mask & (1 << profile), so bit 0 is unused
    and profile 1 is bit 1 (not profile-1).
 6. classify: all comparisons are inclusive at the limit (hi == L fits).
    Since cur <= hi, a failing current value always also fails its range;
    such a term counts for "no" only. Failing current values and failing
    fixed terms are pooled for the smallest type number.
 7. classify (since review A of PR 30, F4: the lobby uses core/tree's limits):
    a fixed limit of 0 means "no limit" (profiles 0: any profile); a listed
    adjustable limit of 0 is a real bound. The member's smallest number of
    members is a fixed term: the terms' `minimum` (type 12) must be at least
    it. The wind-down limit is gone (core/tree's limits have none).
"""
import random
import subprocess
import sys


def choose(target, minimum, mins):
    chosen = list(range(len(mins)))[:target]
    while True:
        n = len(chosen)
        keep = [i for i in chosen if not (mins[i] and mins[i] > n)]
        if len(keep) == n:
            break
        chosen = keep
    return None if len(chosen) < minimum else chosen


def start_rule(target, minimum, deadline_s, now_s, ready):
    if ready >= target:
        return "check"
    if now_s >= deadline_s:
        return "check" if ready >= minimum else "cancel"
    return "wait"


KEYS = ("profile life minimum chan rate lo64 hi64 cur64 lo66 hi66 cur66 lo68 hi68 "
        "cur68 profiles life_min life_max min_members chan_min rate_max L64 L66 L68 "
        "loose").split()


def classify(c):
    fixed_fail = []
    if c["profiles"] and not (c["profiles"] >> c["profile"]) & 1:
        fixed_fail.append(8)
    if c["min_members"] and c["minimum"] < c["min_members"]:
        fixed_fail.append(12)
    if (c["life_min"] and c["life"] < c["life_min"]) or (c["life_max"] and c["life"] > c["life_max"]):
        fixed_fail.append(26)
    if c["chan_min"] and c["chan"] < c["chan_min"]:
        fixed_fail.append(30)
    if c["rate_max"] and c["rate"] > c["rate_max"]:
        fixed_fail.append(32)
    range_fail = []
    for t in (64, 66, 68):
        L = c["L%d" % t]
        if c["cur%d" % t] > L:
            fixed_fail.append(t)
        elif c["hi%d" % t] > L:
            range_fail.append(t)
    if fixed_fail:
        return ("no", min(fixed_fail), 0)
    if range_fail:
        return ("fits_now", min(range_fail), 1 if c["loose"] else 0)
    return ("fits", 0, 1)


# ---- line formats -------------------------------------------------------

def answer(line):
    f = line.split()
    v = [int(x) for x in f[1:]]
    if f[0] == "S":
        r = choose(v[0], v[1], v[3:3 + v[2]])
        return "S none" if r is None else " ".join(["S", str(len(r))] + [str(i) for i in r])
    if f[0] == "R":
        return "R " + start_rule(*v)
    if f[0] == "C":
        cls, term, ready = classify(dict(zip(KEYS, v)))
        return "C %s %d %d" % (cls, term, ready)
    raise ValueError(line)


def near(rng, x, lo, hi):
    """A value equal to x, or just around it, clamped to [lo, hi]."""
    return max(lo, min(hi, x + rng.choice((0, 0, 0, -1, 1, -2, 2))))


def gen_choose(rng):
    target = rng.randint(3, 30)
    minimum = rng.randint(3, target)
    n = rng.choice((rng.randint(0, 40), target, target + rng.randint(1, 5),
                    minimum, minimum - 1, rng.randint(max(0, minimum - 2), target)))
    n = max(0, min(40, n))
    k = min(n, target)
    style = rng.randrange(4)
    mins = []
    for _ in range(n):
        if style == 0 or rng.random() < 0.3:
            m = 0 if rng.random() < 0.5 else rng.randint(1, k + 2)
        elif style == 1:  # cascades: values around the count, from above
            m = near(rng, k - rng.randint(0, 6), 0, 45)
        else:
            m = near(rng, k, 1, 45) if rng.random() < 0.3 else rng.randint(0, k)
        mins.append(m)
    if style == 3 and n >= 5:  # staircase like [5,5,4,4,4]: drop runs many rounds
        s = rng.randint(1, n)
        for j in range(n):
            mins[j] = max(1, min(45, k - (j * s) // n + 1)) if rng.random() < 0.8 else mins[j]
    return "S %d %d %d%s" % (target, minimum, n, "".join(" %d" % m for m in mins))


def gen_rule(rng):
    target = rng.randint(3, 30)
    minimum = rng.randint(3, target)
    deadline = rng.randint(0, 10**6)
    now = near(rng, deadline, 0, 10**7) if rng.random() < 0.6 else rng.randint(0, 10**6)
    ready = near(rng, rng.choice((target, minimum)), 0, 40) if rng.random() < 0.7 else rng.randint(0, 40)
    return "R %d %d %d %d %d" % (target, minimum, deadline, now, ready)


def gen_classify(rng):
    p = 0.85 if rng.random() < 0.5 else 0.5  # chance each limit is at/around the value

    def lim(v, lo, hi, up=True):  # mostly at the boundary on the passing side
        r = rng.random()
        if r < p:
            return v if r < p * 0.6 else near(rng, v, lo, hi)
        return rng.randint(v, hi) if up and r < 0.95 else rng.randint(lo, hi)
    c = {"profile": rng.randint(1, 4), "life": rng.randint(1, 52560),
         "minimum": rng.randint(3, 1000), "chan": rng.randint(546, 10**7),
         "rate": rng.randint(1, 10**6), "loose": rng.randint(0, 1)}
    c["profiles"] = (rng.randint(0, 31) | (1 << c["profile"]) & 31) if rng.random() < p else rng.randint(0, 31)
    c["life_min"] = near(rng, c["life"], 1, 52560) if rng.random() < 0.3 else c["life"] if rng.random() < p else lim(c["life"], 1, 52560)
    c["life_max"] = lim(c["life"], 1, 52560) if rng.random() < p else lim(c["life"], 1, 52560)
    c["min_members"] = min(c["minimum"], lim(c["minimum"], 1, 1000, False)) if rng.random() < 0.8 else near(rng, c["minimum"], 1, 1000)
    c["chan_min"] = min(c["chan"], lim(c["chan"], 546, 10**7, False)) if rng.random() < 0.8 else near(rng, c["chan"], 546, 10**7)
    c["rate_max"] = lim(c["rate"], 1, 10**6)
    for k in ("profiles", "life_min", "life_max", "min_members", "chan_min", "rate_max"):
        if rng.random() < 0.1:
            c[k] = 0                                  # no limit
    for t in (64, 66, 68):
        a, b, d = sorted(rng.randint(0, 10**6) for _ in range(3))
        if rng.random() < 0.2:
            a = b = d = rng.choice((a, 0))
        c["lo%d" % t], c["cur%d" % t], c["hi%d" % t] = a, b, d
        r = rng.random()
        L = (near(rng, d, 0, 10**6) if r < 0.5 else near(rng, b, 0, 10**6) if r < 0.8
             else max(d, rng.randint(0, 10**6)) if r < 0.97 else rng.randint(0, 10**6))
        c["L%d" % t] = L
    return "C " + " ".join(str(c[k]) for k in KEYS)


def check(driver, n, seed):
    rng = random.Random(seed)
    gens = (gen_choose, gen_rule, gen_classify)
    cases = [gens[i % 3](rng) for i in range(n)]
    rng.shuffle(cases)
    out = subprocess.run([driver], input="".join(c + "\n" for c in cases),
                         capture_output=True, text=True).stdout.splitlines()
    mism = 0
    for i, case in enumerate(cases):
        exp = answer(case)
        got = out[i].strip() if i < len(out) else "<missing>"
        if got != exp:
            mism += 1
            if mism <= 20:
                print("MISMATCH case: %s\n  expected: %s\n  got:      %s" % (case, exp, got))
    counts = {k: sum(c[0] == k for c in cases) for k in "SRC"}
    print("model: %d cases, %d choose, %d rule, %d classify, %d mismatches"
          % (n, counts["S"], counts["R"], counts["C"], mism))
    if len(out) != n:
        print("line count differs: expected %d, got %d" % (n, len(out)))
    return 1 if mism or len(out) != n else 0


T6 = ("C 2 1000 3 100000 1000 0 2000 500 0 1000 1000 100 2500 1000 "
      "4 1 52560 0 546 1000 1000 1000 2500 %d")


def selftest():
    cases = [
        ("S 10 3 5 6 6 5 5 5", "S none"),            # 5 -> drop 6s -> 3 -> drop 5s -> 0
        ("S 10 3 6 5 5 4 4 4 0", "S 6 0 1 2 3 4 5"),  # count 6: nobody exceeds 6
        ("S 10 3 6 7 6 0 0 0 0", "S 4 2 3 4 5"),      # two rounds: drop 7, then 6
        ("S 10 3 5 6 5 4 0 0", "S none"),             # three rounds down to 2 < 3
        ("S 4 3 6 0 5 0 0 1 1", "S 3 0 2 3"),         # cut to 4, then drop the 5
        ("S 3 3 2 0 0", "S none"),
        ("S 3 3 0", "S none"),
        ("R 50 30 100 100 30", "R check"),            # now == deadline, ready == min
        ("R 50 30 100 100 29", "R cancel"),
        ("R 50 30 100 99 49", "R wait"),
        ("R 50 30 100 0 50", "R check"),              # target reached early
        (T6 % 0, "C fits_now 64 0"),                  # terms.md T6, strict mode
        (T6 % 1, "C fits_now 64 1"),                  # T6, loose mode
        (T6.replace(" 500 ", " 1500 ", 1) % 1, "C no 64 0"),
        (T6.replace(" 52560 0 ", " 52560 4 ") % 1, "C no 12 0"),      # minimum 3 below 4
        (T6.replace("C 2 1000", "C 2 60000").replace(" 1 52560 ", " 0 0 ") % 0, "C fits_now 64 0"),
        ("C 2 1000 3 100000 1000 0 2000 500 0 1000 1000 100 2500 1000 0 0 0 0 0 0 2000 0 2500 0",
         "C no 66 0"),                               # a listed 0 is a real bound
    ]
    bad = 0
    for line, exp in cases:
        got = answer(line)
        if got != exp:
            bad += 1
            print("FAIL %s\n  expected %s\n  got      %s" % (line, exp, got))
    print("selftest: %d cases, %d failures" % (len(cases), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["check"] and len(a) == 4:
        sys.exit(check(a[1], int(a[2]), int(a[3])))
    if a == ["selftest"]:
        sys.exit(selftest())
    print("usage: lobby_model.py check DRIVER N SEED | selftest")
    sys.exit(2)
