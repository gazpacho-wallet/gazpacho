#!/usr/bin/env python3
"""Static rules for the interface's files (web/), spec/local-api.md 5.4, 12.7 and 23.2 item 16.

    python3 -I tests/web/check_static.py

Fails if any file under web/:
  - has an inline script, an inline style or an inline event handler;
  - uses an HTML sink or runs text as code (innerHTML, document.write, eval, ...);
  - names another host: an address with a scheme anywhere but a comment, or a
    protocol-relative address; every script, stylesheet and request is a path
    on the program's own origin;
  - calls fetch() outside js/api.js, or uses EventSource, WebSocket, cookies,
    the console, or page storage beyond the two allowed uses (the session
    token in sessionStorage, in js/api.js; the theme choice in localStorage);
  - says "staking" (the project's wording rule), comments included;
  - shows the word "passphrase" (owner, 2026-11-25: the person's secret is a
    password; in Bitcoin a passphrase is the BIP39 seed extension, which
    Gazpacho does not use): in any string or HTML text outside comments,
    except identifier-shaped strings (lower case, digits, "_" and "/" only:
    the API's field names, error codes and paths, which are protocol);
and if index.html loads a file the server does not embed, the server embeds
a file index.html does not load, or the word lists differ from the program's.
Standard library only.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB = os.path.join(ROOT, "web")

FORBIDDEN = [
    (r"\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|createContextualFragment|\bsrcdoc\b", "an HTML sink"),
    (r"\beval\s*\(|new\s+Function\b|setTimeout\s*\(\s*[\"'`]|setInterval\s*\(\s*[\"'`]", "text run as code"),
    (r"\bEventSource\b|\bWebSocket\b|\bXMLHttpRequest\b|sendBeacon|\bimportScripts\b", "a transport the interface does not use"),
    (r"document\.cookie", "a cookie"),
    (r"\bconsole\s*\.", "the console (a secret could be logged)"),
    (r"\bindexedDB\b|\bcaches\s*\.", "page storage"),
]
SCHEME = re.compile(r"(?i)\b(?:https?|wss?|ftp)://|\b(?:javascript|data|blob):[^\"'\s]")
PROTO_RELATIVE = re.compile(r"[\"'(=]\s*//[A-Za-z0-9]")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"(?<![:\\])//.*")
STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"' + r"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`")
PROTOCOL_NAME = re.compile(r"[a-z0-9_/]+")


def code_only(text):
    """The text with its comments blanked; line numbers stay."""
    text = BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return LINE_COMMENT.sub("", text)


def files():
    out = []
    for base, _, names in os.walk(WEB):
        for n in sorted(names):
            out.append(os.path.relpath(os.path.join(base, n), WEB).replace(os.sep, "/"))
    return sorted(out)


def main():
    bad = []
    listed = files()
    for rel in listed:
        text = open(os.path.join(WEB, rel), encoding="utf-8", newline="").read()
        if "\r" in text:
            bad.append("%s: CR line endings" % rel)
        if re.search(r"(?i)staking", text):
            bad.append("%s: the word the project never uses" % rel)
        for n, line in enumerate(code_only(text).split("\n"), 1):
            where = "%s:%d" % (rel, n)
            for pat, what in FORBIDDEN:
                if re.search(pat, line):
                    bad.append("%s: %s" % (where, what))
            if SCHEME.search(line):
                bad.append("%s: an address with a scheme outside a comment" % where)
            if PROTO_RELATIVE.search(line):
                bad.append("%s: a protocol-relative address" % where)
            if re.search(r"\bfetch\s*\(", line) and rel != "js/api.js":
                bad.append("%s: fetch() outside js/api.js" % where)
            if "sessionStorage" in line and rel != "js/api.js":
                bad.append("%s: sessionStorage outside js/api.js" % where)
            if "localStorage" in line and "gz-theme" not in line:
                bad.append("%s: localStorage for anything but the theme" % where)
            if rel.endswith(".html"):
                if re.search(r"(?i)passphrase", line):
                    bad.append("%s: the word passphrase in the page (say password)" % where)
            else:
                for s in STRING.findall(line):
                    if re.search(r"(?i)passphrase", s) and not PROTOCOL_NAME.fullmatch(s[1:-1]):
                        bad.append("%s: the word passphrase in shown text (say password): %s" % (where, s[:60]))
            if rel.endswith(".html"):
                if re.search(r"(?i)\son[a-z]+\s*=", line):
                    bad.append("%s: an inline event handler" % where)
                if re.search(r"(?i)\sstyle\s*=|<style\b", line):
                    bad.append("%s: an inline style" % where)
                if re.search(r"(?i)<script\b(?![^>]*\bsrc=)", line):
                    bad.append("%s: an inline script" % where)
                if re.search(r"(?i)<(?:iframe|object|embed|base|form)\b|<meta[^>]+http-equiv", line):
                    bad.append("%s: an element the pages do not use" % where)
    # index.html and the server's list name the same files
    index = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
    refs = re.findall(r'(?:src|href)="([^"]+)"', index)
    loaded = set(r.lstrip("/") for r in refs if r.startswith("/"))
    cmake = open(os.path.join(ROOT, "ports", "api", "CMakeLists.txt"), encoding="utf-8").read()
    m = re.search(r"set\(GZ_INTERFACE_FILES\s+([^)]*)\)", cmake)
    embedded = set(m.group(1).split()) if m else set()
    if embedded != set(listed):
        bad.append("ports/api/CMakeLists.txt embeds %s; web/ holds %s" % (sorted(embedded), listed))
    if loaded | {"index.html"} != embedded:
        bad.append("index.html loads %s; the server embeds %s" % (sorted(loaded), sorted(embedded)))
    for ref in refs:
        if ref.startswith("//") or not (ref.startswith("/") or ref.startswith("#")):
            bad.append("index.html: %s is not a path on this origin" % ref)
    rc = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools", "gen-interface-wordlists.py"), "--check"],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        bad.append(rc.stdout.strip() or "the word lists differ from the program's")
    for b in bad:
        print("FOUND " + b)
    if bad:
        print("FAIL: %d finding(s) in web/" % len(bad))
        return 1
    print("PASS: %d interface files keep the static rules" % len(listed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
