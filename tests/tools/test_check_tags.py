#!/usr/bin/env python3
"""Test for tools/check-tags.py: every way a tag can be used or registered.

    python3 -I tests/tools/test_check_tags.py

Builds small throwaway trees (a PROTOCOL.md 8.2 and a few source files) and
checks the verdict and the findings for each. The tags are built from pieces
so that this file is not a use itself. Standard library only.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tools", "check-tags.py")
P = "gazpacho" + "/"
failures = []

PROTOCOL = """# Map

### 8.1 Other

| Tag | Meaning |
|---|---|
| `{p}ignored` | a table of another section |

### 8.2 Tagged-hash tags and other fixed strings

| Tag | Meaning | Layer | Defined in | State |
|---|---|---|---|---|
| `{p}msg` | Hash a message signature covers | 1 | x | Specified |
| `{p}tree` | Digest of a tree | 3 | Not defined | Name reserved |
| `{p}card` | Was a card | 5 | x | **Reserved**: never reused |
| `{p}draft` | Not yet | 2 | x | Not defined |
{extra}
Other fixed strings, which are plain SHA-256 inputs, not tags:

| String | Use | Defined in |
|---|---|---|
| `{p}v1/salt` | A salt | x |

### 8.3 Feature bits

| `{p}after` | a later table | x |
"""


def tree(files, extra=""):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "spec"))
    with open(os.path.join(d, "spec", "PROTOCOL.md"), "w", encoding="utf-8") as f:
        f.write(PROTOCOL.format(p=P, extra=extra))
    for rel, text in files.items():
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace("@", P))
    return d


def run(d, *args):
    r = subprocess.run([sys.executable, "-I", CHECK, "--root", d] + list(args), capture_output=True, text=True)
    return r.returncode, r.stdout


def expect(name, d, code, present=(), absent=(), args=()):
    got, out = run(d, *args)
    ok = got == code and all(p in out for p in present) and not any(a in out for a in absent)
    if not ok:
        failures.append(name)
        print("FAIL %s: exit %d (wanted %d)\n%s" % (name, got, code, out))
    else:
        print("ok   %s" % name)


# Registered tags, in code, pass; comments, includes and other folders are not uses.
clean = {
    "core/a.c": '#include "@lobby.h"\n#include "@generated.inc"\n  #  include <@x.h>\nstatic const char *t = "@msg"; /* "@nope" */\n'
                '// "@nope2"\nchar c = \'"\'; const char *u = "@tree";\nconst char *h = "@header.h";\n',
    "tools/b.py": 'X = "@msg"  # "@nope3"\nY = b"@card"\nZ = r\'@v1/salt\'\n',
    "core/superscalar/src/s.c": 'const char *s = "@imported";\n',
    "tests/t.c": 'const char *s = "@test-only";\n',
    "docs/d.md": '"@doc"\n',
    "wallet/w.sh": 'echo "@shell"\n',
}
d = tree(clean)
expect("registered tags and non-uses pass", d, 0, present=["0 finding"])

# An unregistered tag in C code is a failure with file and line.
d = tree(dict(clean, **{"core/x.c": 'int a;\nconst char *t = "@session-id";\n'}))
expect("unregistered tag in C", d, 1, present=["core/x.c:2: %ssession-id" % P, "unregistered: %ssession-id" % P])
expect("report mode exits 0", d, 0, present=["core/x.c:2: %ssession-id" % P, "(report only)"], args=["--report"])

# In each scanned folder; and a string concatenated after the prefix is still one literal.
for folder in ("ports", "program", "wallet", "signer", "tools"):
    d = tree({folder + "/sub/y.c": 'const char *t = "@new-%s";\n' % folder})
    expect("unregistered tag under %s/" % folder, d, 1, present=["%s/sub/y.c:1: %snew-%s" % (folder, P, folder)])
d = tree({"tools/y.py": 'T = """@triple"""\n'})
expect("unregistered tag in a Python string", d, 1, present=["tools/y.py:1: %striple" % P])
d = tree({"core/y.h": '#define TAG "@in-header"\n'})
expect("unregistered tag in a header's macro", d, 1, present=["core/y.h:1: %sin-header" % P])

# A tag the table lists but with a state other than Specified or Reserved.
d = tree({"core/x.c": 'const char *t = "@draft";\n'})
expect("tag registered as not defined", d, 1, present=["registered as 'Not defined'"])
# Registered only in a later section's table: not registered.
d = tree({"core/x.c": 'const char *t = "@after";\n'})
expect("tag only in another section", d, 1, present=["%safter (not registered" % P])
d = tree({"core/x.c": 'const char *t = "@ignored";\n'})
expect("tag only in an earlier section", d, 1, present=["%signored (not registered" % P])

# A tag twice in the table.
d = tree({}, extra="| `%smsg` | again | 1 | x | Specified |" % P)
expect("tag registered twice", d, 1, present=["%smsg registered twice" % P])

# A "signed directly" column: each such tag must be in signer.md 3.1.
SIGNED = "| `{p}msg` | m | 1 | x | Specified | host |".format(p=P)
proto_signed = tree({})
with open(os.path.join(proto_signed, "spec", "PROTOCOL.md"), encoding="utf-8") as f:
    text = f.read()
text = text.replace("| Tag | Meaning | Layer | Defined in | State |\n|---|---|---|---|---|",
                    "| Tag | Meaning | Layer | Defined in | State | Signed directly, by which key |\n|---|---|---|---|---|---|")
with open(os.path.join(proto_signed, "spec", "PROTOCOL.md"), "w", encoding="utf-8") as f:
    f.write(text.replace("| `%smsg` | Hash a message signature covers | 1 | x | Specified |" % P, SIGNED))
expect("signed directly, no signer.md", proto_signed, 1, present=["%smsg is signed directly" % P])
os.makedirs(os.path.join(proto_signed, "docs", "notes"))
with open(os.path.join(proto_signed, "docs", "notes", "signer.md"), "w", encoding="utf-8") as f:
    f.write("### 3.1 The table\n\n| Key | May sign |\n|---|---|\n| Host | `%smsg` |\n\n### 3.2 Kinds\n" % P)
expect("signed directly, in signer.md 3.1", proto_signed, 0)
with open(os.path.join(proto_signed, "docs", "notes", "signer.md"), "w", encoding="utf-8") as f:
    f.write("### 3.1 The table\n\nnothing\n\n### 3.2 Kinds\n\n`%smsg`\n" % P)
expect("signed directly, only outside 3.1", proto_signed, 1, present=["%smsg is signed directly" % P])

# No PROTOCOL.md, or no 8.2: a failure.
d = tempfile.mkdtemp()
expect("no PROTOCOL.md", d, 1, present=["missing"])
os.makedirs(os.path.join(d, "spec"))
with open(os.path.join(d, "spec", "PROTOCOL.md"), "w", encoding="utf-8") as f:
    f.write("# nothing\n")
expect("no section 8.2", d, 1, present=["no section 8.2"])

if failures:
    print("RESULT: FAIL (%d)" % len(failures))
    sys.exit(1)
print("RESULT: PASS")
