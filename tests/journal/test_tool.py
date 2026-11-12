"""gz-journal: verdicts and exit codes, and dump never prints record bytes.

    python3 test_tool.py GZ_JOURNAL_BINARY
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crosscheck import entry, header  # noqa: E402

SECRET = bytes.fromhex("5ec2e7f00dfacade") * 4   # stands for a record's contents
failures = 0


def check(cond, what):
    global failures
    if not cond:
        failures += 1
        print("FAIL: " + what)


def tool(*args):
    r = subprocess.run([sys.argv[1], *args], capture_output=True)
    return r.returncode, r.stdout + r.stderr


def journal(extra=b""):
    d = bytearray(header())
    d += entry(1, 1, 0, bytes(8))
    d += entry(3, 1, 0, len(d).to_bytes(8, "big"))
    rec = (0x00020006).to_bytes(4, "big") + len(SECRET).to_bytes(4, "big") + SECRET
    d += entry(2, 1, 1, (1).to_bytes(4, "big") + rec)
    d += entry(3, 1, 0, len(d).to_bytes(8, "big"))
    return d + extra


with tempfile.TemporaryDirectory() as tmp:
    clean = os.path.join(tmp, "clean")
    torn = os.path.join(tmp, "torn")
    corrupt = os.path.join(tmp, "corrupt")
    open(clean, "wb").write(journal())
    open(torn, "wb").write(journal(b"\x00\x00\x00"))
    bad = journal()
    bad[150] ^= 1
    bad += entry(3, 1, 0, len(bad).to_bytes(8, "big"))
    open(corrupt, "wb").write(bad)

    for path, code, word in [(clean, 0, "clean"), (torn, 1, "torn"), (corrupt, 2, "corrupt")]:
        rc, out = tool("verify", path)
        check(rc == code and out.split()[1] == word.encode(), "verify %s: %d %r" % (word, rc, out))
        rc, out = tool("inspect", path)
        check(rc == code and word.encode() in out, "inspect %s" % word)
    rc, out = tool("inspect", "--mainnet", clean)
    check(rc == 2 and b"bad_header" in out, "inspect under the wrong network")

    rc, out = tool("dump", clean)
    check(rc == 0 and b"exposure" in out and b"32 bytes" in out, "dump lists the record")
    for form in (SECRET, SECRET.hex().encode(), SECRET.hex().upper().encode(), SECRET[:8].hex().encode()):
        check(form not in out, "dump printed record bytes (%r)" % form[:16])
    rc, out = tool("bogus", clean)
    check(rc == 2, "an unknown command is refused")
    rc, out = tool("verify", os.path.join(tmp, "missing"))
    check(rc == 2 and b"unreadable" in out, "a missing file")

print("RESULT: %s" % ("PASS" if failures == 0 else "FAIL (%d)" % failures))
sys.exit(1 if failures else 0)
