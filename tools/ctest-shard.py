#!/usr/bin/env python3
"""Split a build's CTest tests (less label slow) into shards for CI.

    python -I tools/ctest-shard.py BUILD_DIR SHARD N [--serial REGEX]

Prints a regular expression for `ctest -R` that selects shard SHARD (1 to N)
or, with SHARD "serial", the tests whose name matches --serial (run alone, in
a shard of their own). The other tests are split by name order, round robin.
Tests joined by a fixture (FIXTURES_SETUP, FIXTURES_REQUIRED,
FIXTURES_CLEANUP) stay in one shard: ctest adds a fixture's setup test to any
run that needs it, so a fixture split across shards would run its setup
twice. A serial test that shares a fixture with others is refused. Prints
nothing for a shard with no tests. Standard library only.
"""
import json
import re
import subprocess
import sys


def main():
    args = sys.argv[1:]
    serial = None
    if "--serial" in args:
        k = args.index("--serial")
        serial = re.compile(args[k + 1])
        del args[k:k + 2]
    if len(args) != 3:
        sys.exit(__doc__)
    build, shard, n = args[0], args[1], int(args[2])
    info = json.loads(subprocess.run(["ctest", "--test-dir", build, "--show-only=json-v1", "-LE", "slow"],
                                     check=True, capture_output=True, text=True).stdout)
    parent = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    names = []
    for t in info.get("tests", []):
        name = t["name"]
        names.append(name)
        parent.setdefault(name, name)
        for p in t.get("properties", []):
            if p.get("name") in ("FIXTURES_SETUP", "FIXTURES_REQUIRED", "FIXTURES_CLEANUP"):
                v = p.get("value")
                for f in (v if isinstance(v, list) else [v]):
                    key = "fixture:" + str(f)
                    parent.setdefault(key, key)
                    union(name, key)
    groups = {}
    for name in sorted(names):
        groups.setdefault(find(name), []).append(name)
    alone, rest = [], []
    for g in sorted(groups.values()):
        if serial and any(serial.search(x) for x in g):
            if len(g) > 1:
                sys.exit("a serial test shares a fixture with others: %s" % ", ".join(g))
            alone.extend(g)
        else:
            rest.append(g)
    if shard == "serial":
        mine = alone
    else:
        i = int(shard)
        if not 1 <= i <= n:
            sys.exit("SHARD is 1 to N, or serial")
        mine = [x for k, g in enumerate(rest) if k % n == i - 1 for x in g]
    if mine:
        print("^(%s)$" % "|".join(re.escape(x) for x in mine))


if __name__ == "__main__":
    main()
