#!/usr/bin/env python3
"""One job's result as Markdown, for agent-run.yml's step summary.

    python3 -I tools/ci-summary.py TITLE STATUS LOG [JUNIT ...]

STATUS is the exit code of the run, LOG its whole output, each JUNIT a JUnit
XML file (ctest --output-junit, Playwright's junit reporter). Prints the
passed and failed test names, and for each failure the tail of its output.
Without JUnit files the names come from the log's own result lines:
tools/valgrind-tests.py ("NAME ok" or "NAME FAILED (exit N)") and the mutant
runners ("killed NAME", "SURVIVED NAME", "BROKEN NAME", "NOBUILD NAME",
"BAD NAME"). The log's tail is printed whenever the run failed. Standard
library only; never fails the job itself.
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

TAIL = 40
LOG_TAIL = 80
LIMIT = 900_000  # GitHub keeps 1 MiB of step summary per step


def tail(text, n):
    lines = (text or "").rstrip("\n").splitlines()
    return "\n".join(lines[-n:])


def fence(text):
    return "```\n" + text.replace("```", "'''") + "\n```\n"


def junit(paths):
    passed, failed, skipped = [], [], []
    for p in paths:
        try:
            root = ET.parse(p).getroot()
        except (OSError, ET.ParseError) as e:
            failed.append(("(%s unreadable: %s)" % (os.path.basename(p), e), ""))
            continue
        for case in root.iter("testcase"):
            name = case.get("name") or "?"
            cls = case.get("classname") or ""
            if cls and cls != name:  # Playwright: the spec file, then the title
                name = "%s > %s" % (cls, name)
            bad = case.find("failure") if case.find("failure") is not None else case.find("error")
            if bad is not None:
                out = "\n".join(x for x in (bad.get("message"), bad.text,
                                            case.findtext("system-out"), case.findtext("system-err")) if x)
                failed.append((name, out))
            elif case.find("skipped") is not None or case.get("status") in ("notrun", "disabled"):
                skipped.append(name)
            else:
                passed.append(name)
    return passed, failed, skipped


def from_log(log):
    passed, failed = [], []
    for line in log.splitlines():
        m = re.match(r"^(\S+)\s{2,}(ok|FAILED)\b", line)
        if m:
            (passed if m.group(2) == "ok" else failed).append((m.group(1), ""))
            continue
        m = re.match(r"^(killed|SURVIVED|BROKEN|NOBUILD|BAD)\s+(\S+)", line)
        if m:
            (passed if m.group(1) == "killed" else failed).append(("%s %s" % (m.group(1), m.group(2)), line))
    return [n for n, _ in passed], failed, []


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    title, status, logp, juns = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
    try:
        log = open(logp, encoding="utf-8", errors="replace").read()
    except OSError:
        log = ""
    juns = [j for j in juns if os.path.exists(j)]
    passed, failed, skipped = junit(juns) if juns else from_log(log)
    ok = status == "0"
    out = ["## %s: %s\n" % (title, "passed" if ok else "FAILED (exit %s)" % status),
           "%d passed, %d failed, %d skipped\n" % (len(passed), len(failed), len(skipped))]
    if failed:
        out.append("**Failed:** " + ", ".join("`%s`" % n for n, _ in failed) + "\n")
    if passed:
        out.append("<details><summary>Passed (%d)</summary>\n\n%s\n</details>\n"
                   % (len(passed), ", ".join("`%s`" % n for n in passed)))
    if skipped:
        out.append("<details><summary>Skipped (%d)</summary>\n\n%s\n</details>\n"
                   % (len(skipped), ", ".join("`%s`" % n for n in skipped)))
    for name, text in failed:
        if text.strip():
            out.append("### %s\n" % name + fence(tail(text, TAIL)))
    if not ok:
        out.append("### Last %d lines of the log\n" % LOG_TAIL + fence(tail(log, LOG_TAIL)))
    page = "\n".join(out)
    if len(page) > LIMIT:
        page = page[:LIMIT] + "\n\n(cut: see the artifact)\n"
    sys.stdout.write(page)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # the summary must never hide the run's own result
        print("summary failed: %s" % e)
        sys.exit(0)
