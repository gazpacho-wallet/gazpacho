#!/usr/bin/env python3
"""T14, program_no_probes (contract-v2.md section 14).

    python3 -I no_probes.py SOURCE_DIR

The program builds against main's core only: no core probe (GZP_CORE_*) is
left in program/ or tests/program/, and no source anywhere names the
withdrawn GZ_RANDOM_OTHER. Exits 1 and lists every finding otherwise.
"""
import os
import re
import sys

PROBE = re.compile(r"\bGZP_CORE_[A-Z_]+")
OLD = re.compile(r"\bGZ_RANDOM_OTHER\b")
CODE = (".c", ".h", ".txt", ".cmake", ".py", ".sh")
SKIP_DIRS = {".git", "core/superscalar", "docs"}


def main():
    root = os.path.abspath(sys.argv[1])
    me = os.path.abspath(__file__)
    found = []
    for dirpath, dirnames, files in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        dirnames[:] = [d for d in dirnames
                       if (d if rel == "." else rel + "/" + d) not in SKIP_DIRS and not d.startswith("build")]
        for f in files:
            path = os.path.join(dirpath, f)
            if not f.endswith(CODE) and f != "CMakeLists.txt" or os.path.abspath(path) == me:
                continue
            relf = os.path.relpath(path, root).replace(os.sep, "/")
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if OLD.search(line):
                    found.append("%s:%d: GZ_RANDOM_OTHER" % (relf, n))
                if relf.startswith(("program/", "tests/program/")) and PROBE.search(line):
                    found.append("%s:%d: core probe %s" % (relf, n, PROBE.search(line).group(0)))
    for f in found:
        print("FOUND " + f)
    if found:
        print("FAIL: %d finding(s)" % len(found))
        return 1
    print("PASS: no core probes, no GZ_RANDOM_OTHER")
    return 0


if __name__ == "__main__":
    sys.exit(main())
