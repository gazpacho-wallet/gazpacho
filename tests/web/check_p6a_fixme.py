#!/usr/bin/env python3
"""The multi-process interface test may stay off only while it waits for P6a.

    python3 -I tests/web/check_p6a_fixme.py SOURCE_DIR              (sources)
    python3 -I tests/web/check_p6a_fixme.py SOURCE_DIR --views DIR  (a run's logs)
    python3 -I tests/web/check_p6a_fixme.py --self-test

tests/web/multiprocess.spec.mjs is marked fixme until the core emits its lobby
view objects (composite-node.md 10). Either way of finding out that it does
fails this check while the spec still carries its fixme line (review of PR 51,
M3), so the test cannot quietly stay off:

  - sources: any C source or header under core/ or program/ that names a lobby
    view kind (GZ_VIEW_LOBBY, GZ_VIEW_HOST_LOBBY), or the NOTIFY code of one
    (GZ_NOTIFY_VIEW with either), apart from the header that numbers them and
    the program's view table, which only receives them;
  - a run (--views): the logs of a real multi-process lobby run
    (program_lobby). Every test-build process that stops says how many view
    NOTIFYs of each kind it received ("views received lobby=N host_lobby=M");
    a lobby view in any of them means the core emits them, however it does it.
    Logs without any such line fail too, so the check cannot go blind.

In CI the browser job sets GZ_PROGRAM, and the spec refuses to be skipped
there without it. Standard library only."""
import os
import re
import sys

FIXME = re.compile(r"^\s*test\.fixme\(", re.M)
NAMES = re.compile(r"\bGZ_VIEW_(?:HOST_)?LOBBY\b")
# where the kinds are numbered, and where the program only receives them
NOT_EMITTERS = {os.path.join("core", "gazpacho", "include", "gazpacho", "command.h"), os.path.join("program", "view.c")}
LOBBY_KINDS = {2, 3}                     # command.h: GZ_VIEW_LOBBY, GZ_VIEW_HOST_LOBBY
VIEW_LINE = re.compile(r"\bview kind=(\d+)\b")
SUMMARY = re.compile(r"\bviews received lobby=(\d+) host_lobby=(\d+)\b")


def source_uses(root):
    found = []
    for top in ("core", "program"):
        for d, _, files in os.walk(os.path.join(root, top)):
            for f in files:
                if not f.endswith((".c", ".h")):
                    continue
                p = os.path.join(d, f)
                rel = os.path.relpath(p, root)
                if rel in NOT_EMITTERS:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    if NAMES.search(fh.read()):
                        found.append(rel)
    return sorted(found)


def run_uses(text):
    kinds = {int(k) for k in VIEW_LINE.findall(text) if int(k) in LOBBY_KINDS}
    for lob, host in SUMMARY.findall(text):
        if int(lob):
            kinds.add(2)
        if int(host):
            kinds.add(3)
    return sorted(kinds)


def logs_text(d):
    out = []
    for dd, _, files in os.walk(d):
        for f in files:
            try:
                with open(os.path.join(dd, f), encoding="utf-8", errors="replace") as fh:
                    out.append(fh.read())
            except OSError:
                pass
    return "\n".join(out)


def verdict(evidence, spec_text):
    """None when fine, else the reason it fails."""
    if evidence and FIXME.search(spec_text):
        return ("the core emits lobby views (%s), so P6a has landed, but tests/web/multiprocess.spec.mjs "
                "is still marked fixme: switch the test on" % "; ".join(evidence))
    return None


def self_test():
    on = "test.fixme(!process.env.GZ_P6A, 'waits for P6a');\n"
    off = "test('x', async () => {});\n"
    assert verdict([], on) is None
    assert verdict(["core/node/src/view.c"], on) is not None
    assert verdict(["core/node/src/view.c"], off) is None
    assert run_uses("h1 view kind=1 id=test version=0\nh1 view kind=2 id=lob_1 version=3\n") == [2]
    assert run_uses("h1 view kind=1 id=x\nh1 view kind=12 id=y\n") == []
    assert run_uses("m1 views received lobby=0 host_lobby=0 all=4\n") == []
    assert run_uses("h1 views received lobby=0 host_lobby=3 all=9\n") == [3]
    assert verdict(["a run: view kinds [2]"], on) is not None
    assert NAMES.search("x = GZ_NOTIFY_VIEW(GZ_VIEW_HOST_LOBBY);") and not NAMES.search("GZ_VIEW_LOBBYX")
    print("PASS: the P6a fixme check's own cases")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    root = argv[1] if len(argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    with open(os.path.join(root, "tests", "web", "multiprocess.spec.mjs"), encoding="utf-8") as fh:
        spec = fh.read()
    evidence = ["sources: " + ", ".join(source_uses(root))] if source_uses(root) else []
    if len(argv) > 3 and argv[2] == "--views":
        if not os.path.isdir(argv[3]):
            print("FAIL: no logs of the lobby run in %s (program_lobby runs first: FIXTURES)" % argv[3])
            return 1
        text = logs_text(argv[3])
        if not SUMMARY.search(text):
            print("FAIL: the lobby run's logs hold no \"views received\" line: the check would not see a lobby view")
            return 1
        kinds = run_uses(text)
        if kinds:
            evidence.append("a run: view kinds %s" % kinds)
    why = verdict(evidence, spec)
    if why:
        print("FAIL: " + why)
        return 1
    print("PASS: the multi-process test is %s" % ("on" if not FIXME.search(spec) else "off only while it waits for P6a"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
