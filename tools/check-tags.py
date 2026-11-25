#!/usr/bin/env python3
"""Fail on a `gazpacho/...` string used in code but not registered in spec/PROTOCOL.md 8.2.

docs/notes/signer.md 7.2, step S1. A BIP 340 tagged-hash tag is never reused
for a second meaning, and every tag is registered in PROTOCOL.md 8.2 before
it is used (8.2's own rule). This check makes the rule mechanical:

  1. It collects every string literal that starts with `gazpacho/` in the C
     and Python code under core/, ports/, program/, wallet/, signer/ and
     tools/, except core/superscalar/ (imported, never edited). Literals in
     comments are not uses. A C `#include` line is not a use, and neither is
     a literal ending in `.h` (a header name).
  2. Every such string must be registered in 8.2: in the tag table with a
     state that says "Specified" or "Reserved", or in its table of other
     fixed strings.
  3. No string may appear twice in the tag table.
  4. If the tag table has a column "Signed directly ..." (signer.md 3.3), every
     tag with an entry there must appear in table 3.1 of docs/notes/signer.md.

Prints one line per finding (FILE:LINE: TAG, or PROTOCOL.md: what) and exits 1
if there is any. With --report it prints the same and exits 0: S1 runs it so
while main still has unregistered strings, which the PR registering them
turns into a failing check.

    python3 -I tools/check-tags.py [--report] [--root DIR]

Standard library only.
"""
import io
import os
import re
import sys
import tokenize

DIRS = ("core", "ports", "program", "wallet", "signer", "tools")
EXCLUDED = ("core/superscalar/",)
PREFIX = "gazpacho" + "/"   # in two pieces, so that this file is not a use itself


def c_literals(text):
    """(line, value) of every string literal outside comments in C source."""
    out = []
    i, n, line = 0, len(text), 1
    at_line_start = True
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            at_line_start = True
            i += 1
            continue
        if at_line_start and c == "#":
            # a preprocessor line: skip an #include, scan the others as code
            m = re.match(r"#\s*include\b[^\n]*", text[i:])
            if m:
                i += m.end()
                continue
        if not c.isspace():
            at_line_start = False
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c and text[j] != "\n":
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if c == '"':
                out.append((line, "".join(buf)))
            i = j + 1
            continue
        i += 1
    return out


def py_literals(text):
    """(line, value) of every string literal in Python source (comments are not tokens)."""
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.STRING:
                m = re.match(r"(?is)^[rbuf]*('''|\"\"\"|'|\")(.*)\1$", tok.string)
                if m:
                    out.append((tok.start[0], m.group(2)))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return out


def uses(root):
    found = []
    for d in DIRS:
        top = os.path.join(root, d)
        for base, dirs, files in os.walk(top):
            dirs.sort()
            rel_base = os.path.relpath(base, root).replace(os.sep, "/") + "/"
            if any(rel_base.startswith(e) for e in EXCLUDED):
                dirs[:] = []
                continue
            for f in sorted(files):
                if not f.endswith((".c", ".h", ".py")):
                    continue
                path = os.path.join(base, f)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                lits = py_literals(text) if f.endswith(".py") else c_literals(text)
                for line, value in lits:
                    if value.startswith(PREFIX) and not value.endswith(".h"):
                        found.append((rel, line, value))
    return found


def registry(root):
    """(tags {tag: state}, plain strings, problems, signed-directly tags) from PROTOCOL.md 8.2."""
    path = os.path.join(root, "spec", "PROTOCOL.md")
    problems, tags, plain, signed = [], {}, set(), []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return tags, plain, ["spec/PROTOCOL.md: missing"], signed
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("### 8.2"))
    except StopIteration:
        return tags, plain, ["spec/PROTOCOL.md: no section 8.2"], signed
    table, header = 0, None
    for l in lines[start + 1:]:
        if l.startswith("#"):
            break
        if not l.startswith("|"):
            if header is not None:
                table += 1
            header = None
            continue
        cells = [c.strip() for c in l.strip().strip("|").split("|")]
        if header is None:
            header = [c.lower() for c in cells]
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue
        m = re.match(r"^`([^`]+)`", cells[0])
        if not m:
            continue
        for name in re.findall(r"`([^`]+)`", cells[0]):
            if table == 0:
                if name in tags:
                    problems.append("spec/PROTOCOL.md 8.2: %s registered twice" % name)
                state = cells[header.index("state")] if "state" in header and header.index("state") < len(cells) else ""
                tags[name] = state
                for k, h in enumerate(header):
                    if h.startswith("signed directly") and k < len(cells) and cells[k] not in ("", "—", "-"):
                        signed.append(name)
            else:
                plain.add(name)
    return tags, plain, problems, signed


def main(argv):
    report = "--report" in argv
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if "--root" in argv:
        root = argv[argv.index("--root") + 1]
    tags, plain, problems, signed = registry(root)
    findings = list(problems)
    unregistered = {}
    for rel, line, value in uses(root):
        state = tags.get(value)
        ok = value in plain or (state is not None and re.search(r"specified|reserved", state, re.I))
        if not ok:
            why = "not registered" if state is None else "registered as '%s'" % state
            findings.append("%s:%d: %s (%s in spec/PROTOCOL.md 8.2)" % (rel, line, value, why))
            unregistered.setdefault(value, []).append(rel)
    if signed:
        note = os.path.join(root, "docs", "notes", "signer.md")
        try:
            with open(note, encoding="utf-8") as fh:
                text = fh.read()
            m = re.search(r"### 3\.1.*?(?=\n### )", text, re.S)
            body = m.group(0) if m else ""
        except OSError:
            body = ""
        for t in signed:
            if "`%s`" % t not in body:
                findings.append("spec/PROTOCOL.md 8.2: %s is signed directly but not in docs/notes/signer.md 3.1" % t)
    for f in findings:
        print(f)
    if unregistered:
        print("unregistered: %s" % ", ".join(sorted(unregistered)))
    print("check-tags: %d finding(s)%s" % (len(findings), " (report only)" if report else ""))
    return 0 if report or not findings else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
