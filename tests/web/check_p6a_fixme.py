#!/usr/bin/env python3
"""The multi-process interface test may stay off only while it waits for P6a.

    python3 -I tests/web/check_p6a_fixme.py [SOURCE_DIR]
    python3 -I tests/web/check_p6a_fixme.py --self-test

tests/web/multiprocess.spec.mjs is marked fixme until the core emits its lobby
view objects (composite-node.md 10). This check fails as soon as any C source
under core/ uses GZ_VIEW_LOBBY (the header that numbers it is a .h,
so only an emitter counts) while the spec still carries its fixme line: P6a has landed, so the test
must be switched on (and the fixme line removed), not left quietly off.
Standard library only."""
import os
import re
import sys

FIXME = re.compile(r"^\s*test\.fixme\(", re.M)
USE = re.compile(r"\bGZ_VIEW_LOBBY\b")


def emitters(root):
    found = []
    for top in ("core",):
        for d, _, files in os.walk(os.path.join(root, top)):
            for f in files:
                if f.endswith(".c"):
                    p = os.path.join(d, f)
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        if USE.search(fh.read()):
                            found.append(os.path.relpath(p, root))
    return sorted(found)


def verdict(uses, spec_text):
    """None when fine, else the reason it fails."""
    if uses and FIXME.search(spec_text):
        return ("GZ_VIEW_LOBBY is used in %s, so P6a has landed, but tests/web/multiprocess.spec.mjs "
                "is still marked fixme: switch the test on" % ", ".join(uses))
    return None


def self_test():
    on = "test.fixme(!process.env.GZ_P6A, 'waits for P6a');\n"
    assert verdict([], on) is None
    assert verdict(["core/node/src/view.c"], on) is not None
    assert verdict(["core/node/src/view.c"], "test('x', async () => {});\n") is None
    assert verdict([], "test('x', async () => {});\n") is None
    print("PASS: the P6a fixme check's own cases")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    root = argv[1] if len(argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    spec = os.path.join(root, "tests", "web", "multiprocess.spec.mjs")
    with open(spec, encoding="utf-8") as fh:
        text = fh.read()
    uses = emitters(root)
    why = verdict(uses, text)
    if why:
        print("FAIL: " + why)
        return 1
    print("PASS: the multi-process test is %s" % ("on" if not FIXME.search(text) else
          "off only while it waits for P6a (no GZ_VIEW_LOBBY in core/ sources)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
