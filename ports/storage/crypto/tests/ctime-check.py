#!/usr/bin/env python3
"""Run sc_test_ctime under valgrind memcheck and allow exactly one branch.

    python3 -I ctime-check.py VALGRIND SC_TEST_CTIME

sc_test_ctime marks every storage secret undefined, so memcheck reports any
branch or memory index that depends on one. One such branch is public by
design and allowed: libsodium 1.0.22's `if (ret != 0)` after the constant-time
crypto_verify_16 in _decrypt_detached (crypto_aead/xchacha20poly1305/
aead_xchacha20poly1305.c, line 111), reached from sc_unseal: whether a tag
verified is what every caller learns anyway.

A suppression file could only name the function, so after a libsodium upgrade
any secret-dependent branch in that function would be hidden too (review A,
L5). So nothing is suppressed: memcheck writes every error as XML, and each
one must be an uninitialised-condition error whose top frame is exactly that
file and line with sc_unseal below it. Anything else, a missing line number
(libsodium is built with -g for this), or a failing test, fails. A libsodium
upgrade has to re-check the line and change ALLOWED. Standard library only.
"""
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ALLOWED = ("aead_xchacha20poly1305.c", 111)
CALLER = "sc_unseal"


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    valgrind, program = sys.argv[1], sys.argv[2]
    fd, xml_path = tempfile.mkstemp(prefix="gz-ctime-", suffix=".xml")
    os.close(fd)
    try:
        r = subprocess.run([valgrind, "--tool=memcheck", "--track-origins=yes", "--xml=yes",
                            "--xml-file=" + xml_path, program], capture_output=True, text=True)
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
            print("FAIL: sc_test_ctime exited with %d" % r.returncode)
            return 1
        root = ET.parse(xml_path).getroot()
    finally:
        os.unlink(xml_path)
    counts = {}
    for pair in root.iter("pair"):
        counts[pair.findtext("unique")] = int(pair.findtext("count") or "0")
    allowed = bad = 0
    for err in root.iter("error"):
        kind = err.findtext("kind")
        stack = err.find("stack")
        frames = stack.findall("frame") if stack is not None else []
        top = frames[0] if frames else None
        # gcc records the file's base name, clang its path below the build folder.
        name = top.findtext("file") if top is not None else None
        where = (os.path.basename(name) if name else None, int(top.findtext("line") or "0") if top is not None else 0)
        callers = [f.findtext("fn") for f in frames]
        n = counts.get(err.findtext("unique"), 1)
        if kind == "UninitCondition" and where == ALLOWED and CALLER in callers:
            allowed += n
            continue
        bad += n
        print("FAIL: %s at %s:%s (%s), %d time(s): %s" % (kind, where[0], where[1],
              " <- ".join(c or "?" for c in callers[:6]), n, err.findtext("what") or err.findtext("xwhat/text")))
    if bad:
        print("FAIL: %d error(s) other than the allowed tag-check branch" % bad)
        return 1
    print("storage ctime: no secret-dependent branch or index; %d allowed at %s:%d (the tag check's outcome)" %
          (allowed, ALLOWED[0], ALLOWED[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
